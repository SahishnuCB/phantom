from datetime import datetime

class Cell():

    def __init__(self, cell_id):
        self.cell_id = cell_id
        self.known_reports = {}

        print(f"{self.cell_id} is online.")


    def create_report(self, report_id, threat_type, source_or_target, confidence, evidence):
        report = {
            "report_id": report_id,
            "reporter_cell_id": self.cell_id,
            "threat_type": threat_type,
            "source_or_target": source_or_target,
            "confidence": confidence,
            "timestamp": datetime.now().isoformat(),
            "evidence": evidence,
        }

        self.known_reports[report_id] = report

        return report


    def receive_report(self, report, sender_cell_id):
        received_report = report.copy()
        received_report["received_from"] = sender_cell_id
        self.known_reports[report["report_id"]] = received_report
        return received_report


Cell_A = Cell("CELL-A")
Cell_B = Cell("CELL-B")

A_report = Cell_A.create_report(
    "R001",
    "port_scan",
    "192.168.1.50",
    0.8,
    "40 ports contacted in 5 seconds",
)



cell_A_report = Cell_A.known_reports["R001"]

cell_B_report = Cell_B.receive_report(cell_A_report, Cell_A.cell_id)
print(f"Cell B received report: {cell_B_report}")

