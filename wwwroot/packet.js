(function () {
    var app = angular.module('packetApp', []);

    app.controller('MainCtrl', ['$http', '$timeout', '$scope', function ($http, $timeout, $scope) {
        var vm = this;
        vm.devices = [];
        vm.packets = [];
        vm.flows = [];
        vm.alerts = [];
        vm.capturing = false;
        vm.selectedDevice = null;
        vm.filter = '';
        vm.activeTab = 'packets';

        vm.selectedPacket = null;
        vm.selectedFlow = null;
        vm.selectedAlert = null;
        vm.packetError = null;

        vm.status = { captured: 0, analyzed: 0, dropped: 0 };

        // Real-time alert notifications (toast + sound, plus desktop notification when the
        // tab is hidden). Only High/Critical fire, throttled per-SID to avoid alert fatigue.
        vm.notifySupported = ('Notification' in window);
        vm.notifyEnabled = false;       // master toggle for in-page toast + sound
        var osNotifyGranted = false;    // OS desktop notifications allowed
        var audioCtx = null;
        var lastNotified = {};          // sid -> last notify time (ms)
        var NOTIFY_THROTTLE_MS = 5000;

        var ws = null;
        var pendingGridUpdate = false;
        var statusPoll = null;

        // Function to render verdict badges
        const renderVerdict = (verdict) => {
            let badgeClass = "badge bg-success";
            if (verdict === "Suspicious") badgeClass = "badge bg-warning text-dark";
            if (verdict === "Malicious") badgeClass = "badge bg-danger";
            return gridjs.html(`<span class="${badgeClass}">${verdict}</span>`);
        };

        // Function to render severity badges
        const renderSeverity = (severity) => {
            let badgeClass = "badge bg-secondary";
            if (severity === "Critical" || severity === "High") badgeClass = "badge bg-danger";
            else if (severity === "Medium") badgeClass = "badge bg-warning text-dark";
            else if (severity === "Low") badgeClass = "badge bg-info";
            return gridjs.html(`<span class="${badgeClass}">${severity}</span>`);
        };

        const packetGrid = new gridjs.Grid({
            columns: ["Time", "Src", "Dest", "Protocol", "Len", { name: "Verdict", formatter: renderVerdict }, { name: "id", hidden: true }],
            data: [], sort: true, resizable: true,
            className: { table: 'table table-centered table-nowrap mb-0 table-hover' }
        }).render($("#packet-grid")[0]);

        const flowGrid = new gridjs.Grid({
            columns: ["Source", "Destination", "Protocol", "Packets", "Bytes", "Duration (s)", "SYN", "FIN", "RST", { name: "Verdict", formatter: renderVerdict }],
            data: [], sort: true, resizable: true,
            className: { table: 'table table-centered table-nowrap mb-0 table-hover' }
        }).render($("#flow-grid")[0]);

        const alertGrid = new gridjs.Grid({
            columns: ["Time", { name: "Severity", formatter: renderSeverity }, "SID", "Signature", "Src", "Dest", "Category"],
            data: [], sort: true, resizable: true,
            className: { table: 'table table-centered table-nowrap mb-0 table-hover' }
        }).render($("#alert-grid")[0]);

        packetGrid.on('rowClick', (...args) => {
            const e = args[0];
            const rowData = args[1].cells;

            // Remove selected class from all rows in packet grid, highlight the clicked one
            $('#packet-grid .gridjs-tr').removeClass('gridjs-tr-selected');
            $(e.target).closest('.gridjs-tr').addClass('gridjs-tr-selected');

            // The hidden id column is the last cell
            const id = rowData[rowData.length - 1].data;
            vm.loadPacketDetail(id);
        });

        flowGrid.on('rowClick', (...args) => {
            const e = args[0];
            const rowData = args[1].cells;

            // Remove selected class from all rows in flow grid, highlight the clicked one
            $('#flow-grid .gridjs-tr').removeClass('gridjs-tr-selected');
            $(e.target).closest('.gridjs-tr').addClass('gridjs-tr-selected');

            const match = vm.flows.find(f => f.src === rowData[0].data && f.dest === rowData[1].data);
            $timeout(() => { vm.selectedFlow = match; });
        });

        alertGrid.on('rowClick', (...args) => {
            const e = args[0];
            const rowData = args[1].cells;

            // Remove selected class from all rows in alert grid, highlight the clicked one
            $('#alert-grid .gridjs-tr').removeClass('gridjs-tr-selected');
            $(e.target).closest('.gridjs-tr').addClass('gridjs-tr-selected');

            // Match on SID + signature + src to find the alert object
            const match = vm.alerts.find(a => a.sid === rowData[2].data && a.signature === rowData[3].data && a.src === rowData[4].data);
            $timeout(() => { vm.selectedAlert = match; });
        });

        vm.switchTab = function (tab) {
            vm.activeTab = tab;
            requestGridUpdate();
        };

        function requestGridUpdate() {
            if (pendingGridUpdate) return;
            pendingGridUpdate = true;
            setTimeout(() => {
                if (vm.activeTab === 'packets') {
                    // Create a true copy of the data to prevent reference collision
                    const packetData = [...vm.packets].map(p => [
                        p.timestamp, p.src, p.dest, p.protocol, p.length, p.verdict, p.id
                    ]);

                    packetGrid.updateConfig({ data: packetData }).forceRender();
                } else if (vm.activeTab === 'flows') {
                    const flowData = [...vm.flows].map(f => [
                        f.src, f.dest, f.protocol, f.packetCount, f.byteCount,
                        parseFloat(f.duration).toFixed(2),
                        f.syn, f.fin, f.rst, f.verdict
                    ]);

                    flowGrid.updateConfig({ data: flowData }).forceRender();
                } else if (vm.activeTab === 'alerts') {
                    const alertData = [...vm.alerts].map(a => [
                        a.timestamp, a.severity, a.sid, a.signature, a.src, a.dest, a.category
                    ]);

                    alertGrid.updateConfig({ data: alertData }).forceRender();
                }
                pendingGridUpdate = false;
                $scope.$applyAsync();
            }, 500);
        }

        vm.loadDevices = function () {
            $http.get('/devices').then(function (res) {
                vm.devices = res.data;
                if (vm.devices.length) vm.selectedDevice = vm.devices[0].index;

                // Initialize Select2 after Angular finishes rendering options
                $timeout(function () {
                    var $select = $('#device-select');

                    $select.select2();

                    // Sync Select2 changes back to Angular
                    $select.on('select2:select', function (e) {
                        $timeout(function () {
                            // Dispatch a native change event so Angular's ng-model picks it up correctly
                            $select[0].dispatchEvent(new Event('change'));
                        });
                    });
                });
            });
        };

        // Load packet detail on demand
        vm.loadPacketDetail = function (id) {
            if (id == null) return;
            vm.packetError = null;
            vm.selectedPacket = null;
            $http.get('/packet/' + id).then(function (res) {
                vm.selectedPacket = res.data;
            }, function (err) {
                if (err.status === 404) {
                    vm.packetError = 'Packet detail no longer available (expired).';
                } else {
                    vm.packetError = 'Failed to load packet detail.';
                }
            });
        };

        vm.openWs = function () {
            // If already open or connecting, do nothing
            if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
                return;
            }

            // Force close any existing broken/closed socket reference just to be safe
            if (ws) {
                try { ws.close(); } catch (e) { }
            }

            // No credentials are embedded here. The page is already behind HTTP Basic auth, and
            // browsers forward the cached Authorization header on the same-origin WebSocket
            // handshake � the server's middleware uses it. Keeps the password out of client code.
            var wsScheme = (location.protocol === 'https:') ? 'wss://' : 'ws://';
            ws = new WebSocket(wsScheme + location.host + '/ws');

            ws.onerror = function () {
                console.error('WebSocket error � check capture is started and credentials are correct.');
            };

            ws.onmessage = function (e) {
                try {
                    var obj = JSON.parse(e.data);
                    if (obj.type !== 'batch') return;

                    // Packets: newest first, cap at 5000
                    if (obj.packets && obj.packets.length) {
                        for (var i = 0; i < obj.packets.length; i++) {
                            vm.packets.unshift(obj.packets[i]);
                        }
                        if (vm.packets.length > 5000) vm.packets.length = 5000;
                    }

                    // Flows: upsert keyed by .key, cap at 2000
                    if (obj.flows && obj.flows.length) {
                        for (var j = 0; j < obj.flows.length; j++) {
                            var flow = obj.flows[j];
                            var existing = vm.flows.find(f => f.key === flow.key);
                            if (existing) {
                                angular.extend(existing, flow);
                            } else {
                                vm.flows.unshift(flow);
                            }
                        }
                        if (vm.flows.length > 2000) vm.flows.length = 2000;
                    }

                    // Alerts: newest first, cap at 1000
                    if (obj.alerts && obj.alerts.length) {
                        for (var k = 0; k < obj.alerts.length; k++) {
                            vm.alerts.unshift(obj.alerts[k]);
                            notifyAlert(obj.alerts[k]);
                        }
                        if (vm.alerts.length > 1000) vm.alerts.length = 1000;
                    }

                    // Single debounced grid update per batch (critical for performance)
                    requestGridUpdate();
                } catch (err) { console.error(err); }
            };

            ws.onclose = function () {
                ws = null;
            };
        };

        // Poll status (~2s) while capturing for live counters
        function startStatusPoll() {
            if (statusPoll) return;
            statusPoll = setInterval(function () {
                if (!vm.capturing) return;
                $http.get('/status').then(function (res) {
                    vm.status = res.data;
                }, function () { /* ignore */ });
            }, 2000);
        }

        function stopStatusPoll() {
            if (statusPoll) {
                clearInterval(statusPoll);
                statusPoll = null;
            }
        }

        vm.start = function () {
            if (vm.selectedDevice == null) return alert('Select device');
            $http.post('/start?devIndex=' + vm.selectedDevice + '&filter=' + encodeURIComponent(vm.filter || ''))
                .then(function () {
                    vm.capturing = true;
                    vm.openWs();
                    startStatusPoll();
                }, function () { alert('Failed to start capture'); });
        };

        vm.stop = function () {
            $http.post('/stop').then(function () {
                vm.capturing = false;
                stopStatusPoll();
            });
        };

        vm.clear = function () {
            if (!confirm("Are you sure?")) return;
            vm.packets = [];
            vm.flows = [];
            vm.alerts = [];
            vm.selectedPacket = null;
            vm.selectedFlow = null;
            vm.selectedAlert = null;
            vm.packetError = null;
            requestGridUpdate();
        };

        vm.formatDetails = function (obj) {
            if (!obj) return "";
            let cleanObj = angular.copy(obj);
            if (cleanObj.details) {
                return cleanObj.details + "\n\nRaw JSON Data:\n" + JSON.stringify(cleanObj, null, 2);
            }
            return JSON.stringify(cleanObj, null, 2);
        };

        vm.triggerUpload = function () {
            $('#pcapUploadBtn').click();
        };

        vm.handleUpload = function (files) {
            if (!files || files.length === 0) return;

            var formData = new FormData();
            formData.append('file', files[0]);

            $http.post('/upload', formData, {
                transformRequest: angular.identity,
                headers: { 'Content-Type': undefined } // Forces browser to set boundary automatically
            }).then(function () {
                vm.openWs(); // ensure websocket open
            }, function (err) {
                alert('Upload failed: ' + (err.data.error || err.statusText));
            });

            // Reset the input
            $('#pcapUploadBtn').val('');
        };

        // --- Alert notifications ------------------------------------------------

        // Web Audio is gated behind a user gesture, so prime the context on the same
        // click that enables notifications. Also primes OS-notification permission.
        function primeAudio() {
            try {
                if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
                if (audioCtx.state === 'suspended') audioCtx.resume();
            } catch (e) { /* audio unavailable */ }
        }

        function playBeep(critical) {
            if (!audioCtx) return;
            try {
                var osc = audioCtx.createOscillator();
                var gain = audioCtx.createGain();
                osc.type = 'sine';
                osc.frequency.value = critical ? 880 : 600;
                gain.gain.value = 0.07;
                osc.connect(gain); gain.connect(audioCtx.destination);
                osc.start();
                osc.stop(audioCtx.currentTime + 0.18);
            } catch (e) { /* ignore */ }
        }

        // Lightweight Bootstrap-styled toast (managed manually so we don't depend on the
        // bootstrap JS bundle being present). Uses textContent to avoid HTML injection.
        function showToast(severity, title, body) {
            var $container = $('#toast-container');
            if (!$container.length) return;
            var isWarning = (severity === 'Medium');
            var bg = (severity === 'Critical' || severity === 'High') ? 'bg-danger text-white'
                   : isWarning ? 'bg-warning' : 'bg-info text-white';
            // The header normally has its own (white) background; make it transparent so it
            // inherits the toast colour, and match the text/close-button contrast.
            var headerText = isWarning ? '' : ' text-white';
            var closeCls = isWarning ? 'btn-close' : 'btn-close btn-close-white';

            var $close = $('<button>', { type: 'button', 'class': closeCls, 'aria-label': 'Close' });
            var $el = $('<div>', { 'class': 'toast show ' + bg, role: 'alert' }).append(
                $('<div>', { 'class': 'toast-header bg-transparent border-0' + headerText }).append(
                    $('<strong>', { 'class': 'me-auto', text: 'PacketSniffer Alert' }),
                    $('<small>', { text: 'now' }),
                    $close),
                $('<div>', { 'class': 'toast-body' }).append(
                    $('<strong>', { 'class': 'd-block', text: title }), // .text() escapes - no HTML injection
                    $('<span>', { text: body })));

            $close.on('click', function () { $el.remove(); });
            $container.append($el);
            setTimeout(function () { $el.remove(); }, 6000);
        }

        function notifyAlert(a) {
            if (!vm.notifyEnabled || !a) return;
            if (a.severity !== 'High' && a.severity !== 'Critical') return;

            var now = Date.now();
            if (lastNotified[a.sid] && (now - lastNotified[a.sid]) < NOTIFY_THROTTLE_MS) return;
            lastNotified[a.sid] = now;

            var title = a.severity + ': ' + a.sid + ' ' + a.signature;
            var body = (a.src || '?') + ' → ' + (a.dest || '?') + '  [' + a.category + ']';

            showToast(a.severity, title, body);
            playBeep(a.severity === 'Critical');

            // OS notification only when the tab is hidden, so we don't double up with the toast.
            // The SID is used as the tag, mirroring the server-side (sid,src,dst) suppression.
            if (osNotifyGranted && document.visibilityState === 'hidden') {
                try { new Notification(title, { body: body, tag: a.sid }); } catch (e) { /* ignore */ }
            }
        }

        vm.enableNotifications = function () {
            // Toggle: a second click turns alert notifications back off.
            if (vm.notifyEnabled) {
                vm.notifyEnabled = false;
                return;
            }

            primeAudio();
            vm.notifyEnabled = true; // toast + sound work regardless of OS permission
            if (vm.notifySupported && Notification.permission !== 'granted') {
                Notification.requestPermission().then(function (perm) {
                    osNotifyGranted = (perm === 'granted');
                });
            } else if (vm.notifySupported) {
                osNotifyGranted = (Notification.permission === 'granted');
            }
        };

        vm.loadDevices();
    }]);
})();
