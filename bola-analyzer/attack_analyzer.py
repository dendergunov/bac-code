import yaml


class AttackAnalyzer:
    def __init__(self):
        self.bola_spec = dict()
        self.attack_spec = dict()
        self.operations = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']
        self.attack_structure_example = {
            'name': '',
            'type': '',
            'check_rule': '',
            'description': '',
            'examples': []
        }

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
                print("Endpoint found:", key)
                self.__parse_endpoint(key, value)

    def __parse_endpoint(self, path, content):
        # Call attack checker methods
        content: dict
        print(content)
        self.__authorization_token_manipulation(path, content)

    def __authorization_token_manipulation(self, path, content):
        content: dict
        target_operations = []
        for operation in self.operations:
            if content.get(operation) is not None:
                operation_content = content.get(operation)
                if operation_content.get('method_level_properties') is not None:
                    for operation_property in operation_content.get('method_level_properties'):
                        if operation_property['name'] == 'authorization required' and \
                                operation_property['value'] is True:
                            target_operations.append(operation)
        if len(target_operations):
            attack = self.attack_structure_example.copy()
            attack['name'] = 'Authorization token manipulation'
            attack['type'] = 'Authorization token manipulation'
            attack['target_operation'] = target_operations
            attack['check_rule'] = "Endpoint's operation requires authorization"
            attack['description'] = 'Request is repeated with authorization token of another user to check whether ' \
                                    'authorization is incorrect and non-permitted access is granted '
            if self.attack_spec.get(path) is None:
                self.attack_spec[path] = []
            self.attack_spec[path].append(attack)

    def save_output(self, savepath):
        with open(savepath, 'w') as file:
            yaml.safe_dump(self.attack_spec, file, sort_keys=False)
