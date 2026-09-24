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
        self.good_reports = {}
        self.reputation_history = {}
        self.threat_profiles = {}

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

                    self.reduce_bad_report_count(existing_report["reporter_cell_id"])
                    self.reduce_bad_report_count(received_report["reporter_cell_id"])

                    existing_reporter = existing_report["reporter_cell_id"]
                    received_reporter = received_report["reporter_cell_id"]

                    self.record_good_report(existing_reporter)
                    self.record_good_report(received_reporter)

                    self.reduce_bad_report_count(existing_reporter)
                    self.reduce_bad_report_count(received_reporter)

                    self.save_reputation_snapshot(existing_reporter)
                    self.save_reputation_snapshot(received_reporter)

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

    def reduce_bad_report_count(self, cell_id):
        if cell_id in self.bad_reports:
            self.bad_reports[cell_id] -= 1

            if self.bad_reports[cell_id] <= 0:
                del self.bad_reports[cell_id]

    def record_good_report(self, cell_id):
        if cell_id not in self.good_reports:
            self.good_reports[cell_id] = 1
        else:
            self.good_reports[cell_id] += 1

    def get_good_report_count(self, cell_id):
        return self.good_reports.get(cell_id, 0)

    def get_bad_report_count(self, cell_id):
        return self.bad_reports.get(cell_id, 0)

    def get_reliability_ratio(self, cell_id):
        good_reports = self.get_good_report_count(cell_id)
        bad_reports = self.get_bad_report_count(cell_id)

        total_reports = good_reports + bad_reports

        if total_reports == 0:
            return 0.5

        return good_reports / total_reports

    def calculate_reputation_score(self, cell_id):
        trust_score = self.trust_scores.get(cell_id, 0.5)
        reliability_ratio = self.get_reliability_ratio(cell_id)

        reputation_score = (
            trust_score * 0.6
            + reliability_ratio * 0.4
        )

        return round(reputation_score, 3)

    def classify_reputation(self, cell_id):
        reputation_score = self.calculate_reputation_score(cell_id)

        if reputation_score >= 0.8:
            return "highly_trusted"

        if reputation_score >= 0.6:
            return "trusted"

        if reputation_score >= 0.4:
            return "neutral"

        if reputation_score >= 0.2:
            return "suspicious"

        return "untrusted"

    def get_reputation_summary(self, cell_id):
        return {
            "cell_id": cell_id,
            "trust_score": round(
                self.trust_scores.get(cell_id, 0.5),
                3
            ),
            "good_reports": self.get_good_report_count(cell_id),
            "bad_reports": self.get_bad_report_count(cell_id),
            "reliability_ratio": round(
                self.get_reliability_ratio(cell_id),
                3
            ),
            "reputation_score": self.calculate_reputation_score(cell_id),
            "reputation_class": self.classify_reputation(cell_id),
        }

    def save_reputation_snapshot(self, cell_id):
        if cell_id not in self.reputation_history:
            self.reputation_history[cell_id] = []

        snapshot = self.get_reputation_summary(cell_id)

        snapshot["timestamp"] = datetime.now().isoformat()

        self.reputation_history[cell_id].append(snapshot)

        return snapshot

    def print_reputation_summary(self, cell_id):
        summary = self.get_reputation_summary(cell_id)

        print(f"\nReputation summary for {cell_id}")
        print("-" * 40)
        print(f"Trust score       : {summary['trust_score']}")
        print(f"Good reports      : {summary['good_reports']}")
        print(f"Bad reports       : {summary['bad_reports']}")
        print(f"Reliability ratio : {summary['reliability_ratio']}")
        print(f"Reputation score  : {summary['reputation_score']}")
        print(f"Classification    : {summary['reputation_class']}")

    def get_threat_key(self, report):
        return (
            report["threat_type"],
            report["source_or_target"]
        )

    def calculate_combined_confidence(self, reports):
        remaining_uncertainty = 1.0

        for report in reports:
            reporter = report["reporter_cell_id"]

            if reporter == self.cell_id:
                reporter_trust = 1.0
            else:
                reporter_trust = self.trust_scores.get(
                    reporter,
                    0.5
                )

            weighted_confidence = (
                report["confidence"] * reporter_trust
            )

            remaining_uncertainty *= (
                1 - weighted_confidence
            )

        combined_confidence = (
            1 - remaining_uncertainty
        )

        return round(
            min(1.0, combined_confidence),
            3
        )

    def classify_threat_severity(
        self,
        combined_confidence,
        reporter_count
    ):
        if (
            combined_confidence >= 0.9
            and reporter_count >= 3
        ):
            return "critical"

        if combined_confidence >= 0.75:
            return "high"

        if combined_confidence >= 0.5:
            return "medium"

        return "low"

    def classify_threat_status(
        self,
        combined_confidence,
        reporter_count
    ):
        if (
            combined_confidence >= 0.8
            and reporter_count >= 2
        ):
            return "confirmed"

        if combined_confidence >= 0.5:
            return "suspected"

        return "unverified"

    def rebuild_threat_profile(
        self,
        threat_type,
        source_or_target
    ):
        matching_reports = []

        for report in self.known_reports.values():
            if (
                report["threat_type"] == threat_type
                and
                report["source_or_target"]
                == source_or_target
            ):
                matching_reports.append(report)

        threat_key = (
            threat_type,
            source_or_target
        )

        if not matching_reports:
            self.threat_profiles.pop(
                threat_key,
                None
            )
            return None

        reporters = set()

        for report in matching_reports:
            reporters.add(
                report["reporter_cell_id"]
            )

        combined_confidence = (
            self.calculate_combined_confidence(
                matching_reports
            )
        )

        severity = self.classify_threat_severity(
            combined_confidence,
            len(reporters)
        )

        status = self.classify_threat_status(
            combined_confidence,
            len(reporters)
        )

        profile = {
            "threat_type": threat_type,
            "source_or_target": source_or_target,
            "report_count": len(
                matching_reports
            ),
            "reporter_count": len(reporters),
            "reporters": sorted(reporters),
            "combined_confidence":
                combined_confidence,
            "severity": severity,
            "status": status,
            "last_updated":
                datetime.now().isoformat(),
        }

        self.threat_profiles[
            threat_key
        ] = profile

        return profile

    def rebuild_all_threat_profiles(self):
        threat_keys = set()

        for report in self.known_reports.values():
            threat_keys.add(
                self.get_threat_key(report)
            )

        self.threat_profiles = {}

        for threat_type, source_or_target in threat_keys:
            self.rebuild_threat_profile(
                threat_type,
                source_or_target
            )

    def get_threat_profile(
        self,
        threat_type,
        source_or_target
    ):
        threat_key = (
            threat_type,
            source_or_target
        )

        return self.threat_profiles.get(
            threat_key
        )

    def print_threat_profile(
        self,
        threat_type,
        source_or_target
    ):
        profile = self.get_threat_profile(
            threat_type,
            source_or_target
        )

        if profile is None:
            print("Threat profile not found.")
            return

        print("\nThreat Profile")
        print("-" * 40)

        print(
            f"Threat type        : "
            f"{profile['threat_type']}"
        )

        print(
            f"Source / target    : "
            f"{profile['source_or_target']}"
        )

        print(
            f"Reports            : "
            f"{profile['report_count']}"
        )

        print(
            f"Independent cells  : "
            f"{profile['reporter_count']}"
        )

        print(
            f"Reporters          : "
            f"{', '.join(profile['reporters'])}"
        )

        print(
            f"Confidence         : "
            f"{profile['combined_confidence']}"
        )

        print(
            f"Severity           : "
            f"{profile['severity']}"
        )

        print(
            f"Status             : "
            f"{profile['status']}"
        )


if __name__ == "__main__":
    Cell_A = Cell("Cell_A")
    Cell_B = Cell("Cell_B")
    Cell_C = Cell("Cell_C")
    Cell_D = Cell("Cell_D")

    Cell_A.add_neighbour(Cell_B)
    Cell_C.add_neighbour(Cell_B)
    Cell_D.add_neighbour(Cell_B)

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

    Cell_D.create_report(
        "R003",
        "port_scan",
        "192.168.1.50",
        0.6,
        "35 ports contacted in 5 seconds",
    )

    Cell_A.send_report("R001", Cell_B)
    Cell_C.send_report("R002", Cell_B)
    Cell_D.send_report("R003", Cell_B)

    Cell_B.rebuild_all_threat_profiles()

    Cell_B.print_threat_profile("port_scan", "192.168.1.50")
