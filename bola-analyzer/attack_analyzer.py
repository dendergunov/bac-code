import yaml
from copy import deepcopy

import endpoint


# ToDo: Move attack names to distinct namespace and use internal constant corresponding ids instead
class AttackAnalyzer:
    def __init__(self):
        self.bola_spec = dict()
        self.attack_spec = dict()
        self.paths_processed = 0
        self.attacks_proposed = 0

    def estimate_attacks(self, filename):
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
                    endpoint_analyzer.parse_endpoint()
                    if len(endpoint_analyzer.attack_spec):
                        self.attack_spec[path] = {'count': len(endpoint_analyzer.attack_spec),
                                                  'attacks': deepcopy(endpoint_analyzer.attack_spec)}
                        self.attacks_proposed += self.attack_spec[path]['count']
                    print("Endpoint found:", path)
                    if self.attack_spec.get(path) is not None:
                        print("Attacks proposed for that endpoint:", self.attack_spec[path]['count'])
                    else:
                        print("Attacks proposed for that endpoint:", 0)
                    self.paths_processed += 1
        print("Total paths processed:", self.paths_processed)
        print("Total attacks proposed:", self.attacks_proposed)
        self.attack_spec['total_paths'] = self.paths_processed
        self.attack_spec['attack_proposed'] = self.attacks_proposed

    def save_output(self, savepath):
        with open(savepath, 'w') as file:
            yaml.safe_dump(self.attack_spec, file, sort_keys=False)
