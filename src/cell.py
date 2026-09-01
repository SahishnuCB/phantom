from datetime import datetime

class Cell():

    def __init__(self, cell_id):
        self.cell_id = cell_id
        self.known_reports = {}
        self.neighbours = []
        self.max_hops = 5

        print(f"{self.cell_id} is online.")


    def create_report(self, report_id, threat_type, source_or_target, confidence, evidence):
        report = {
            "report_id": report_id,
            "hop_count": 0,
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
        received_report["hop_count"] += 1
        self.known_reports[report["report_id"]] = received_report

        if received_report["hop_count"] >= self.max_hops:
            print(f"Report {report['report_id']} reached max hops at {self.cell_id}.")
            return received_report

        for neighbour in self.neighbours:
            if neighbour.cell_id != sender_cell_id:
                neighbour.receive_report(received_report, self.cell_id)

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



if __name__ == "__main__":
    Cell_A = Cell("CELL-A")
    Cell_B = Cell("CELL-B")
    Cell_C = Cell("CELL-C")
    Cell_D = Cell("CELL-D")
    Cell_E = Cell("CELL-E")
    Cell_F = Cell("CELL-F")

    Cell_A.add_neighbour(Cell_B)

    Cell_B.add_neighbour(Cell_A)
    Cell_B.add_neighbour(Cell_C)

    Cell_C.add_neighbour(Cell_B)
    Cell_C.add_neighbour(Cell_D)

    Cell_D.add_neighbour(Cell_C)
    Cell_D.add_neighbour(Cell_E)

    Cell_E.add_neighbour(Cell_D)
    Cell_E.add_neighbour(Cell_F)

    Cell_F.add_neighbour(Cell_E)

    Cell_A.create_report(
        "R001",
        "port_scan",
        "192.168.1.50",
        0.8,
        "40 ports contacted in 5 seconds",
    )

    Cell_A.send_report("R001", Cell_B)

    print("CELL-A:", Cell_A.known_reports)
    print("CELL-B:", Cell_B.known_reports)
    print("CELL-C:", Cell_C.known_reports)
    print("CELL-D:", Cell_D.known_reports)
    print("CELL-E:", Cell_E.known_reports)
    print("CELL-F:", Cell_F.known_reports)
