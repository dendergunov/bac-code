import yaml
from copy import deepcopy

import endpoint


# ToDo: Move attack names to distinct namespace and use internal constant corresponding ids instead
class AttackAnalyzer:
    def __init__(self):
        self.bola_spec = dict()
        self.attack_spec = dict()
        self.no_attacks_spec = dict()
        self.paths_processed = 0
        self.attacks_proposed = 0
        self.attack_types_proposed = 0
        self.attacks_count_dict = {"Enumeration without a priori knowledge": 0,
                                   "Enumeration with a priori knowledge": 0,
                                   "Add/Change file extension": 0,
                                   "Wildcard replacement": 0,
                                   "Array appending": 0,
                                   "Verb tampering non-specified": 0,
                                   "Verb tampering parameters exchange": 0,
                                   "Authorization token manipulation": 0,
                                   "Parameter pollution": 0}

    def estimate_attacks(self, filename, **disable_attacks):
        """Public method to process OpenAPI 3.0 specification annotated with BOLA/IDOR properties.
        Use save_output(savepath) to save YAML with estimated attacks
        """
        try:
            f = open(filename, 'r')
        except OSError:
            print("Could not open/read file", filename)
            exit(2)
        self.bola_spec = yaml.load(f, Loader=yaml.SafeLoader)

        if self.bola_spec.get('paths') is not None:
            print("Paths OpenAPI object found!")
            for path, path_schema in self.bola_spec['paths'].items():
                if path.startswith('/'):
                    endpoint_analyzer = endpoint.EndpointAttackAnalyzer(path, path_schema)
                    endpoint_analyzer.parse_endpoint(**disable_attacks)
                    if len(endpoint_analyzer.attack_spec):
                        self.attack_spec[path] = {'count': len(endpoint_analyzer.attack_spec),
                                                  'attacks': deepcopy(endpoint_analyzer.attack_spec)}
                        self.attacks_proposed += self.attack_spec[path]['count']
                        attack_types_proposed = 0
                        if endpoint_analyzer.attack_simple_enum > 0:
                            attack_types_proposed += 1
                            self.attacks_count_dict["Enumeration without a priori knowledge"] += 1
                        if endpoint_analyzer.attack_complex_enum > 0:
                            attack_types_proposed += 1
                            self.attacks_count_dict["Enumeration with a priori knowledge"] += 1
                        if endpoint_analyzer.attack_file_ext > 0:
                            attack_types_proposed += 1
                            self.attacks_count_dict["Add/Change file extension"] += 1
                        if endpoint_analyzer.attack_wildcard > 0:
                            attack_types_proposed += 1
                            self.attacks_count_dict["Wildcard replacement"] += 1
                        if endpoint_analyzer.attack_array_enum > 0:
                            attack_types_proposed += 1
                            self.attacks_count_dict["Array appending"] += 1
                        if endpoint_analyzer.attack_vtns > 0:
                            attack_types_proposed += 1
                            self.attacks_count_dict["Verb tampering non-specified"] += 1
                        if endpoint_analyzer.attack_vtpe > 0:
                            attack_types_proposed += 1
                            self.attacks_count_dict[
                                "Verb tampering parameters exchange"] += 1
                        if endpoint_analyzer.attack_atm > 0:
                            attack_types_proposed += 1
                            self.attacks_count_dict["Authorization token manipulation"] += 1
                        if endpoint_analyzer.attack_pp > 0:
                            attack_types_proposed += 1
                            self.attacks_count_dict["Parameter pollution"] += 1
                        self.attack_spec[path]['count'] = attack_types_proposed
                        self.attack_types_proposed += attack_types_proposed
                    else:
                        print("Endpoint", path, "without attacks")
                        self.no_attacks_spec[path] = self.bola_spec.get('paths')[path]
                    print("Endpoint found:", path)
                    if self.attack_spec.get(path) is not None:
                        print("Attacks proposed for that endpoint:", self.attack_spec[path]['count'])
                    else:
                        print("Attacks proposed for that endpoint:", 0)
                    self.paths_processed += 1
        print("Total paths processed:", self.paths_processed)
        print("Total attacks_types proposed:", self.attack_types_proposed)
        print("Total attack proposed:", self.attacks_proposed)
        self.attack_spec['attacked_paths'] = len(self.attack_spec.keys())
        self.attack_spec['not_attacked_paths'] = len(self.no_attacks_spec.keys())
        self.attack_spec['total_paths'] = self.paths_processed
        self.attack_spec['attacks_proposed'] = self.attack_types_proposed
        f.close()

    def save_output(self, savepath):
        with open(savepath, 'w') as file:
            yaml.safe_dump(self.attack_spec, file, sort_keys=False)
        with open('noattacks.yaml', 'w') as noattackfile:
            yaml.safe_dump(self.no_attacks_spec, noattackfile, sort_keys=False)
