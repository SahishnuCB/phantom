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

        for existing_report in self.known_reports.values():
            if existing_report["report_id"] != received_report["report_id"]:
                if self.is_same_threat(existing_report, received_report):
                    print(
                        f"Corroborating reports found: "
                        f"{existing_report['report_id']} and {received_report['report_id']}"
                    )

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


    def decay_confidence(self, report_id, decay_factor):
        if report_id in self.known_reports:
            self.known_reports[report_id]["confidence"] *= decay_factor

        return self.known_reports[report_id]["confidence"]


    def is_same_threat(self, report1, report2):
        time1 = datetime.fromisoformat(report1["timestamp"])
        time2 = datetime.fromisoformat(report2["timestamp"])
        time_difference = abs((time1 - time2).total_seconds())

        if (report1["threat_type"] == report2["threat_type"]
            and report1["source_or_target"] == report2["source_or_target"]
            and time_difference <= 60):
            return True

        return False


if __name__ == "__main__":
    Cell_A = Cell("CELL-A")
    Cell_B = Cell("CELL-B")
    Cell_C = Cell("CELL-C")

    Cell_A.add_neighbour(Cell_B)
    Cell_C.add_neighbour(Cell_B)

    Cell_A.create_report(
        "R001",
        "port_scan",
        "192.168.1.50",
        0.8,
        "40 ports contacted in 5 seconds",
    )

    Cell_C.create_report(
        "R002",
        "port_scan",
        "192.168.1.50",
        0.7,
        "38 ports contacted in 5 seconds",
    )

    Cell_A.send_report("R001", Cell_B)
    Cell_C.send_report("R002", Cell_B)

    print("\nCELL-B known reports:")
    print(Cell_B.known_reports)
