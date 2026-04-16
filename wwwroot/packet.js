(function () {
    var app = angular.module('packetApp', []);

    app.controller('MainCtrl', ['$http', '$timeout', '$scope', function ($http, $timeout, $scope) {
        var vm = this;
        vm.devices = [];
        vm.packets = [];
        vm.flows = [];
        vm.capturing = false;
        vm.selectedDevice = null;
        vm.filter = '';
        vm.activeTab = 'packets';

        vm.selectedPacket = null;
        vm.selectedFlow = null;

        var ws = null;
        var pendingGridUpdate = false;

        // Function to render verdict badges
        const renderVerdict = (verdict) => {
            let badgeClass = "badge bg-success";
            if (verdict === "Suspicious") badgeClass = "badge bg-warning text-dark";
            if (verdict === "Malicious") badgeClass = "badge bg-danger";
            return gridjs.html(`<span class="${badgeClass}">${verdict}</span>`);
        };

        const packetGrid = new gridjs.Grid({
            columns: ["Time", "Src", "Dst", "Proto", "Len", { name: "Verdict", formatter: renderVerdict }],
            data: [], sort: true, resizable: true,
            className: { table: 'table table-centered table-nowrap mb-0 table-hover' }
        }).render(document.getElementById("packet-grid"));

        const flowGrid = new gridjs.Grid({
            columns: ["Source", "Destination", "Proto", "Packets", "Bytes", "Duration (s)", "SYN", "FIN", "RST", { name: "Verdict", formatter: renderVerdict }],
            data: [], sort: true, resizable: true,
            className: { table: 'table table-centered table-nowrap mb-0 table-hover' }
        }).render(document.getElementById("flow-grid"));

        packetGrid.on('rowClick', (...args) => {
            const e = args[0]; // Native PointerEvent
            const rowData = args[1].cells;

            // Remove selected class from all rows in packet grid
            document.querySelectorAll('#packet-grid .gridjs-tr').forEach(r => r.classList.remove('gridjs-tr-selected'));
            // Add selected class to the clicked row
            const clickedRow = e.target.closest('.gridjs-tr');
            if (clickedRow) clickedRow.classList.add('gridjs-tr-selected');

            const match = vm.packets.find(p => p.timestamp === rowData[0].data && p.length === rowData[4].data);
            $timeout(() => { vm.selectedPacket = match; });
        });

        flowGrid.on('rowClick', (...args) => {
            const e = args[0]; // Native PointerEvent
            const rowData = args[1].cells;

            // Remove selected class from all rows in flow grid
            document.querySelectorAll('#flow-grid .gridjs-tr').forEach(r => r.classList.remove('gridjs-tr-selected'));
            // Add selected class to the clicked row
            const clickedRow = e.target.closest('.gridjs-tr');
            if (clickedRow) clickedRow.classList.add('gridjs-tr-selected');

            const match = vm.flows.find(f => f.src === rowData[0].data && f.dest === rowData[1].data);
            $timeout(() => { vm.selectedFlow = match; });
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
                    const packetData = vm.packets.map(p => [
                        p.timestamp, p.src, p.dest, p.protocol, p.length, p.verdict
                    ]);
                    packetGrid.updateConfig({ data: packetData }).forceRender();
                } else {
                    const flowData = vm.flows.map(f => [
                        f.src, f.dest, f.protocol, f.packetCount, f.byteCount,
                        parseFloat(f.duration).toFixed(2),
                        f.syn, f.fin, f.rst, f.verdict
                    ]);
                    flowGrid.updateConfig({ data: flowData }).forceRender();
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

        vm.openWs = function () {
            if (ws && ws.readyState === 1) return;
            ws = new WebSocket('ws://' + location.host + '/ws?auth=' + btoa("admin:password"));
            ws.onmessage = function (e) {
                try {
                    var obj = JSON.parse(e.data);
                    if (obj.type == 'flow') {
                        var existing = vm.flows.find(f => f.key === obj.key);
                        if (existing) angular.extend(existing, obj);
                        else {
                            vm.flows.unshift(obj);
                            if (vm.flows.length > 2000) vm.flows.pop();
                        }
                    } else {
                        vm.packets.unshift(obj);
                        if (vm.packets.length > 5000) vm.packets.pop();
                    }
                    requestGridUpdate();
                } catch (err) { console.error(err); }
            };
        };

        vm.start = function () {
            if (vm.selectedDevice == null) return alert('Select device');
            $http.post('/start?devIndex=' + vm.selectedDevice + '&filter=' + encodeURIComponent(vm.filter || ''))
                .then(function () {
                    vm.capturing = true;
                    vm.openWs();
                }, function () { alert('Failed to start capture'); });
        };

        vm.stop = function () {
            $http.post('/stop').then(function () { vm.capturing = false; });
        };

        vm.clear = function () {
            if (!confirm("Are you sure?")) return;
            vm.packets = [];
            vm.flows = [];
            vm.selectedPacket = null;
            vm.selectedFlow = null;
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

        vm.loadDevices();
    }]);
})();