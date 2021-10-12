import yaml
from copy import deepcopy

import endpoint


# ToDo: Move attack names to distinct namespace and use internal constant corresponding ids instead
# Proposition:
#   Move part of functionality to endpoint analyzer because almost every function uses path argument to pass
#   When it is better to instantiate an object of class Endpoint Analyzer and uses its internal attributes and return
#   Endpoint's attacks file
class AttackAnalyzer:
    def __init__(self):
        self.bola_spec = dict()
        self.attack_spec = dict()

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

        for key, value in self.bola_spec.items():
            if key.startswith('/'):
                endpoint_analyzer = endpoint.EndpointAttackAnalyzer(key, value)
                endpoint_analyzer.parse_endpoint()
                if len(endpoint_analyzer.attack_spec):
                    self.attack_spec[key] = {'attacks': deepcopy(endpoint_analyzer.attack_spec)}

    def save_output(self, savepath):
        with open(savepath, 'w') as file:
            yaml.safe_dump(self.attack_spec, file, sort_keys=False)
