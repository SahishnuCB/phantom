from datetime import datetime

class Cell():

    def __init__(self, cell_id):
        self.cell_id = cell_id
        self.known_reports = {}
        self.neighbours = []

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
        if report["report_id"] in self.known_reports:
            print(f"Report {report['report_id']} already known by {self.cell_id}.")
            return
        
        received_report = report.copy()
        received_report["received_from"] = sender_cell_id
        self.known_reports[report["report_id"]] = received_report
        return received_report


    def send_report(self, report_id, target_cell):
        if report_id in self.known_reports:
            target_cell.receive_report(self.known_reports[report_id], self.cell_id)
            return self.known_reports[report_id]

        print(f"Report {report_id} not found in {self.cell_id}.")
        return None


    def add_neighbour(self, neighbour_cell):
        if neighbour_cell not in self.neighbours:
            self.neighbours.append(neighbour_cell)


    def send_to_neighbours(self, report_id):
        if report_id not in self.known_reports:
            print(f"Report {report_id} not found in {self.cell_id}.")
            return

        for neighbour in self.neighbours:
            neighbour.send_report(report_id, neighbour)


Cell_A = Cell("CELL-A")
Cell_B = Cell("CELL-B")

A_report = Cell_A.create_report(
    "R001",
    "port_scan",
    "192.168.1.50",
    0.8,
    "40 ports contacted in 5 seconds",
)

print(Cell_B.known_reports)

print("-" * 80)

Cell_A.send_report("R001", Cell_B)
print(Cell_B.known_reports)

print("-" * 80)

Cell_A.add_neighbour(Cell_B)
for neighbour in Cell_A.neighbours:
    print(f"{Cell_A.cell_id} has neighbour {neighbour.cell_id}.")
