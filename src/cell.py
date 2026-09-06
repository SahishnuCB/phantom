from datetime import datetime

class Cell():

    def __init__(self, cell_id):
        self.cell_id = cell_id
        self.known_reports = {}
        self.neighbours = []
        self.max_hops = 5
        self.report_archive = []
        self.trust_scores = {}
        self.bad_reports = {}

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
            "last_supported": datetime.now().isoformat(),
            "corroborated": False,
        }

        self.known_reports[report_id] = report

        return report


    def receive_report(self, report, sender_cell_id):
        if sender_cell_id not in self.trust_scores:
            self.trust_scores[sender_cell_id] = 0.5

        if report["report_id"] in self.known_reports:
            print(f"Report {report['report_id']} already known by {self.cell_id}.")
            return

        received_report = report.copy()
        received_report["received_from"] = sender_cell_id
        received_report["hop_count"] += 1

        for existing_report in self.known_reports.values():
            if existing_report["report_id"] != received_report["report_id"]:
                if self.is_same_threat(existing_report, received_report):
                    existing_report["corroborated"] = True
                    received_report["corroborated"] = True
                    print(
                        f"Corroborating reports found: "
                        f"{existing_report['report_id']} and {received_report['report_id']}"
                    )

                    sender_trust = self.trust_scores[sender_cell_id]

                    effective_support = (
                        received_report["confidence"] * sender_trust
                    )

                    trust_increment = 0.05 * effective_support

                    self.boost_confidence(existing_report["report_id"], effective_support)

                    self.increase_trust(existing_report["reporter_cell_id"], trust_increment)
                    self.increase_trust(received_report["reporter_cell_id"], trust_increment)

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


    def boost_confidence(self, report_id, boost_factor):
        if report_id in self.known_reports:
            self.known_reports[report_id]["confidence"] = (
                self.known_reports[report_id]["confidence"] + (1 - self.known_reports[report_id]["confidence"]) * boost_factor
            )

            self.known_reports[report_id]["last_supported"] = datetime.now().isoformat()

            return self.known_reports[report_id]["confidence"]

        return None


    def is_same_threat(self, report1, report2):
        time1 = datetime.fromisoformat(report1["timestamp"])
        time2 = datetime.fromisoformat(report2["timestamp"])
        time_difference = abs((time1 - time2).total_seconds())

        if (report1["threat_type"] == report2["threat_type"]
            and report1["source_or_target"] == report2["source_or_target"]
            and time_difference <= 60):
            return True

        return False


    def decay_all_reports(self,decay_factor):
        for report_id in list(self.known_reports):

            last_supported = datetime.fromisoformat(self.known_reports[report_id]["last_supported"])
            time_difference = (
                datetime.now() - last_supported
                ).total_seconds()

            if time_difference > 2:
                self.decay_confidence(report_id, decay_factor)
                if self.known_reports[report_id]["confidence"] < 0.3:
                    self.archive_report(report_id)


    def archive_report(self, report_id):
        if report_id in self.known_reports:
            report = self.known_reports[report_id]

            trust_decrement = 0.05 * (1 - self.trust_scores[report["reporter_cell_id"]])

            if report["corroborated"] == False:
                reporter_cell_id = report["reporter_cell_id"]

                if reporter_cell_id not in self.bad_reports:
                    self.bad_reports[reporter_cell_id] = 1
                else:
                    self.bad_reports[reporter_cell_id] += 1

                bad_report_count = self.bad_reports[reporter_cell_id]

                trust_decrement = (
                    0.05 * bad_report_count * (1 - self.trust_scores[reporter_cell_id])
                    )

                self.decrease_trust(report["reporter_cell_id"], trust_decrement)

            self.report_archive.append(self.known_reports[report_id])
            del self.known_reports[report_id]


    def increase_trust(self, cell_id, increment):
        if cell_id in self.trust_scores:
            self.trust_scores[cell_id] = min(1.0, self.trust_scores[cell_id] + increment)


    def decrease_trust(self, cell_id, decrement):
        if cell_id in self.trust_scores:
            self.trust_scores[cell_id] = max(0.0, self.trust_scores[cell_id] - decrement)


if __name__ == "__main__":
    import time

    Cell_A = Cell("Cell_A")
    Cell_B = Cell("Cell_B")

    Cell_A.add_neighbour(Cell_B)

    reports = [
        ("R001", 0.32),
        ("R002", 0.32),
        ("R003", 0.32),
    ]

    for report_id, confidence in reports:
        Cell_A.create_report(
            report_id,
            "port_scan",
            "192.168.1.50",
            confidence,
            f"Test evidence for {report_id}",
        )

        Cell_A.send_report(report_id, Cell_B)

        print(f"\nBefore archiving {report_id}")
        print(f"Trust: {Cell_B.trust_scores}")
        print(f"Bad reports: {Cell_B.bad_reports}")

        time.sleep(3)

        Cell_B.decay_all_reports(0.9)

        print(f"\nAfter archiving {report_id}")
        print(f"Trust: {Cell_B.trust_scores}")
        print(f"Bad reports: {Cell_B.bad_reports}")
