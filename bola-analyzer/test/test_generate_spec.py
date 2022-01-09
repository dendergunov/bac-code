import unittest

import os
import sys
import inspect

import time

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import annotator
import attack_analyzer
import attack_technique


class GenerationTestCase(unittest.TestCase):
    def test_one(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "generated_specs", "1.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "generated_specs", "1_properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(os.path.join(currentdir, "generated_specs",
                                                               "1_properties.yaml"))
        attack_analyzer_instance.save_output(os.path.join(currentdir, "generated_specs",
                                                          "1_tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        print("Path processed:", property_analyzer.paths_found)
        print("Methods processed:", property_analyzer.methods_found)
        print("Identifiers recognized:", property_analyzer.identifiers_found)
        print()
        print("Parameters found:", len(property_analyzer.parameters_dict.keys()))
        print("Parameters:", property_analyzer.parameters_dict)
        print()
        print("Identifiers found:", len(property_analyzer.identifiers_dict.keys()))
        print("identifiers:", property_analyzer.identifiers_dict)
        print()
        print("Non-identifiers found:", len(property_analyzer.no_identifiers_dict.keys()))
        print("non-identifiers:", property_analyzer.no_identifiers_dict)
        print()
        print("Done in", end - start, "seconds")
        print(attack_analyzer_instance.attacks_count_dict)

    def test_two(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "generated_specs", "2.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "generated_specs", "2_properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(os.path.join(currentdir, "generated_specs",
                                                               "2_properties.yaml"))
        attack_analyzer_instance.save_output(os.path.join(currentdir, "generated_specs",
                                                          "2_tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        print("Path processed:", property_analyzer.paths_found)
        print("Methods processed:", property_analyzer.methods_found)
        print("Identifiers recognized:", property_analyzer.identifiers_found)
        print()
        print("Parameters found:", len(property_analyzer.parameters_dict.keys()))
        print("Parameters:", property_analyzer.parameters_dict)
        print()
        print("Identifiers found:", len(property_analyzer.identifiers_dict.keys()))
        print("identifiers:", property_analyzer.identifiers_dict)
        print()
        print("Non-identifiers found:", len(property_analyzer.no_identifiers_dict.keys()))
        print("non-identifiers:", property_analyzer.no_identifiers_dict)
        print()
        print("Done in", end - start, "seconds")
        print(attack_analyzer_instance.attacks_count_dict)

    def test_three(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "generated_specs", "3.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "generated_specs", "3_properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(os.path.join(currentdir, "generated_specs",
                                                               "3_properties.yaml"))
        attack_analyzer_instance.save_output(os.path.join(currentdir, "generated_specs",
                                                          "3_tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        print("Path processed:", property_analyzer.paths_found)
        print("Methods processed:", property_analyzer.methods_found)
        print("Identifiers recognized:", property_analyzer.identifiers_found)
        print()
        print("Parameters found:", len(property_analyzer.parameters_dict.keys()))
        print("Parameters:", property_analyzer.parameters_dict)
        print()
        print("Identifiers found:", len(property_analyzer.identifiers_dict.keys()))
        print("identifiers:", property_analyzer.identifiers_dict)
        print()
        print("Non-identifiers found:", len(property_analyzer.no_identifiers_dict.keys()))
        print("non-identifiers:", property_analyzer.no_identifiers_dict)
        print()
        print("Done in", end - start, "seconds")
        print(attack_analyzer_instance.attacks_count_dict)


if __name__ == '__main__':
    unittest.main()
