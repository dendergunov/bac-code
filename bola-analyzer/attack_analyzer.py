import yaml
from copy import deepcopy

import endpoint
import attack_technique


class AttackAnalyzer:
    def __init__(self):
        self.bola_spec = dict()
        self.attack_spec = dict()
        self.no_attacks_spec = dict()
        self.paths_processed = 0
        self.attacks_proposed = 0
        self.attack_types_proposed = 0
        self.attacks_count_dict = {attack_technique.enum_black_box: 0,
                                   attack_technique.enum_gray_box: 0,
                                   attack_technique.manipulate_file_extension: 0,
                                   attack_technique.replace_wildcard: 0,
                                   attack_technique.append_list: 0,
                                   attack_technique.tamper_verb_non_spec: 0,
                                   attack_technique.tamper_verb_exchange: 0,
                                   attack_technique.manipulate_auth_data: 0,
                                   attack_technique.parameter_pollution: 0}

    def estimate_attacks(self, filename, **disable_attacks):
        """Public method to process OpenAPI 3.0 specification annotated with BOLA/IDOR properties.
        Use save_output(savepath) to save YAML with estimated attacks
        """
        try:
            f = open(filename, 'r')
            self.bola_spec = yaml.load(f, Loader=yaml.SafeLoader)

            if self.bola_spec.get('paths') is not None:
                print("Paths OpenAPI object found!")
                for path, path_schema in self.bola_spec['paths'].items():
                    if path.startswith('/'):
                        # Run analyzer
                        endpoint_analyzer = endpoint.EndpointAttackAnalyzer(path, path_schema)
                        endpoint_analyzer.parse_endpoint(**disable_attacks)

                        # Check attacks proposed after parsing
                        if len(endpoint_analyzer.attack_spec):
                            self.attack_spec[path] = {'count': len(endpoint_analyzer.attack_spec),
                                                      'attacks': deepcopy(endpoint_analyzer.attack_spec)}
                            self.attacks_proposed += self.attack_spec[path]['count']
                            attack_types_proposed = 0
                            for attack in endpoint_analyzer.attacks_count_dict.keys():
                                if endpoint_analyzer.attacks_count_dict[attack] > 0:
                                    attack_types_proposed += 1
                                    self.attacks_count_dict[attack] += 1
                            self.attack_spec[path]['count'] = attack_types_proposed
                            self.attack_types_proposed += attack_types_proposed
                        else:
                            print("Endpoint", path, "without attacks")
                            self.no_attacks_spec[path] = self.bola_spec.get('paths')[path]

                        # Debug output
                        print("Endpoint found:", path)
                        if self.attack_spec.get(path) is not None:
                            print("Attacks proposed for that endpoint:", self.attack_spec[path]['count'])
                        else:
                            print("Attacks proposed for that endpoint:", 0)
                        self.paths_processed += 1

            # Spec debug output
            print("Total paths processed:", self.paths_processed)
            print("Total attacks_types proposed:", self.attack_types_proposed)
            print("Total attack proposed:", self.attacks_proposed)
            self.attack_spec['attacked_paths'] = len(self.attack_spec.keys())
            self.attack_spec['not_attacked_paths'] = len(self.no_attacks_spec.keys())
            self.attack_spec['total_paths'] = self.paths_processed
            self.attack_spec['attacks_proposed'] = self.attack_types_proposed
            f.close()
        except OSError:
            print("Could not open/read file", filename)
            exit(2)

    def save_output(self, savepath):
        with open(savepath, 'w') as file:
            yaml.safe_dump(self.attack_spec, file, sort_keys=False)
        with open('noattacks.yaml', 'w') as noattackfile:
            yaml.safe_dump(self.no_attacks_spec, noattackfile, sort_keys=False)
