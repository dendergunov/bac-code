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


class FunctionalTestCase(unittest.TestCase):
    def test_enumeration_without(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "enumeration_without", "api_spec.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "enumeration_without", "properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(os.path.join(currentdir, "enumeration_without", "properties.yaml"),
                                                  authorization_token_manipulation_off=True,
                                                  verb_tampering_non_specified_off=True,
                                                  verb_tampering_parameters_exchange_off=True,
                                                  parameter_pollution_off=True)
        attack_analyzer_instance.save_output(os.path.join(currentdir, "enumeration_without", "tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        self.assertTrue(list(attack_analyzer_instance.attack_spec.values())[0]['attacks'][0]['name'] == 'Enumeration')

    def test_enumeration_with(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "enumeration_with", "api_spec.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "enumeration_with", "properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(os.path.join(currentdir, "enumeration_with", "properties.yaml"),
                                                  authorization_token_manipulation_off=True,
                                                  verb_tampering_non_specified_off=True,
                                                  verb_tampering_parameters_exchange_off=True,
                                                  parameter_pollution_off=True)
        attack_analyzer_instance.save_output(os.path.join(currentdir, "enumeration_with", "tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        self.assertTrue(list(attack_analyzer_instance.attack_spec.values())[0]['attacks'][0]['name'] == 'Enumeration')

    def test_authorization_token_manipulation(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "authorization_token_manipulation", "api_spec.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "authorization_token_manipulation", "properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(os.path.join(currentdir, "authorization_token_manipulation",
                                                               "properties.yaml"),
                                                  enumeration_off=True,
                                                  verb_tampering_non_specified_off=True,
                                                  verb_tampering_parameters_exchange_off=True,
                                                  parameter_pollution_off=True)
        attack_analyzer_instance.save_output(os.path.join(currentdir, "authorization_token_manipulation", "tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        self.assertTrue(list(attack_analyzer_instance.attack_spec.values())[0]['attacks'][0]['name'] ==
                        attack_technique.manipulate_auth_data)

    def test_verb_tampering_non_specified(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "verb_tampering_non_specified", "api_spec.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "verb_tampering_non_specified", "properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(os.path.join(currentdir, "verb_tampering_non_specified",
                                                               "properties.yaml"),
                                                  enumeration_off=True,
                                                  authorization_token_manipulation_off=True,
                                                  verb_tampering_parameters_exchange_off=True,
                                                  parameter_pollution_off=True)
        attack_analyzer_instance.save_output(os.path.join(currentdir, "verb_tampering_non_specified", "tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        self.assertTrue(list(attack_analyzer_instance.attack_spec.values())[0]['attacks'][0]['name'] ==
                        attack_technique.tamper_verb_non_spec)

    def test_verb_tampering_parameters_exchange(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "verb_tampering_parameters_exchange", "api_spec.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "verb_tampering_parameters_exchange", "properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(os.path.join(currentdir, "verb_tampering_parameters_exchange",
                                                               "properties.yaml"),
                                                  enumeration_off=True,
                                                  authorization_token_manipulation_off=True,
                                                  verb_tampering_non_specified_off=True,
                                                  parameter_pollution_off=True)
        attack_analyzer_instance.save_output(os.path.join(currentdir, "verb_tampering_parameters_exchange",
                                                          "tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        self.assertTrue(list(attack_analyzer_instance.attack_spec.values())[0]['attacks'][0]['name'] ==
                        "Adding parameters and body used in another HTTP Methods")

    def test_parameter_pollution(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "parameter_pollution", "api_spec.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "parameter_pollution", "properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(os.path.join(currentdir, "parameter_pollution",
                                                               "properties.yaml"),
                                                  enumeration_off=True,
                                                  authorization_token_manipulation_off=True,
                                                  verb_tampering_non_specified_off=True,
                                                  verb_tampering_parameters_exchange_off=True
                                                  )
        attack_analyzer_instance.save_output(os.path.join(currentdir, "parameter_pollution",
                                                          "tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        self.assertTrue(list(attack_analyzer_instance.attack_spec.values())[0]['attacks'][0]['name'] ==
                        "Parameter pollution")

    def test_enumeration_array(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "enumeration_array", "api_spec.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "enumeration_array", "properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(os.path.join(currentdir, "enumeration_array", "properties.yaml"),
                                                  authorization_token_manipulation_off=True,
                                                  verb_tampering_non_specified_off=True,
                                                  verb_tampering_parameters_exchange_off=True,
                                                  parameter_pollution_off=True)
        attack_analyzer_instance.save_output(os.path.join(currentdir, "enumeration_array", "tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        self.assertTrue(list(attack_analyzer_instance.attack_spec.values())[0]['attacks'][0]['name'] == 'Enumeration')

    def test_enumeration_file(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "enumeration_file", "api_spec.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "enumeration_file", "properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(os.path.join(currentdir, "enumeration_file", "properties.yaml"),
                                                  authorization_token_manipulation_off=True,
                                                  verb_tampering_non_specified_off=True,
                                                  verb_tampering_parameters_exchange_off=True,
                                                  parameter_pollution_off=True)
        attack_analyzer_instance.save_output(os.path.join(currentdir, "enumeration_file", "tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        self.assertTrue(list(attack_analyzer_instance.attack_spec.values())[0]['attacks'][0]['name'] == 'Enumeration')

    def test_enumeration_wildcard(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "enumeration_wildcard", "api_spec.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "enumeration_wildcard", "properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(os.path.join(currentdir, "enumeration_wildcard", "properties.yaml"),
                                                  authorization_token_manipulation_off=True,
                                                  verb_tampering_non_specified_off=True,
                                                  verb_tampering_parameters_exchange_off=True,
                                                  parameter_pollution_off=True)
        attack_analyzer_instance.save_output(os.path.join(currentdir, "enumeration_wildcard", "tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        self.assertTrue(list(attack_analyzer_instance.attack_spec.values())[0]['attacks'][0]['name'] == 'Enumeration')

    def test_no_vulnerabilities(self):
        start = time.time()
        property_analyzer = annotator.OpenAPISpecAnnotator()
        property_analyzer.parse_spec(os.path.join(currentdir,
                                                  "no_vulnerability", "api_spec.yaml"))
        property_analyzer.save_spec(os.path.join(currentdir, "no_vulnerability", "properties.yaml"))

        attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
        attack_analyzer_instance.estimate_attacks(
            os.path.join(currentdir, "no_vulnerability", "properties.yaml"))
        attack_analyzer_instance.save_output(os.path.join(currentdir, "no_vulnerability", "tests.yaml"))
        end = time.time()

        print("Done in", end - start, "seconds")
        self.assertTrue(
            attack_analyzer_instance.attack_spec['attacks_proposed'] == 0)


if __name__ == '__main__':
    unittest.main()
