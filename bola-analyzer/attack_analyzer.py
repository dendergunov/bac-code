import yaml
from copy import deepcopy


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
        self.__verb_tampering_non_specified(path, content)
        self.__verb_tampering_parameters_exchange(path, content)

    def __authorization_token_manipulation(self, path, content):
        """path - endpoint's path (OpenAPI PATH object)
        content - endpoint's content"""
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
            attack = deepcopy(self.attack_structure_example)
            attack['name'] = 'Authorization token manipulation'
            attack['type'] = 'Authorization token manipulation'
            attack['target_operation'] = deepcopy(target_operations)
            attack['check_rule'] = "Endpoint's operation requires authorization"
            attack['description'] = 'Request is repeated with authorization token of another user to check whether ' \
                                    'authorization is incorrect and non-permitted access is granted '
            if self.attack_spec.get(path) is None:
                self.attack_spec[path] = []
            self.attack_spec[path].append(attack)

    def __verb_tampering_non_specified(self, path, content):
        """Check for verb tampering attack: operation is changed to one without definition in specification
        path - endpoint's path (OpenAPI PATH object)
        content - endpoint's content"""
        content: dict
        non_specified_operation = [operation for operation in self.operations if content.get(operation) is None]
        for operation in self.operations:
            if content.get(operation) is not None:
                identifiers_used = self.__extract_property(content.get(operation), 'method_level_properties',
                                                           'identifiers used in operation')
                if identifiers_used['value'] != 'zero':
                    attack = deepcopy(self.attack_structure_example)
                    attack['name'] = 'Change HTTP Method (Verb tampering)'
                    attack['type'] = 'Endpoint verb tampering'
                    attack['target_operation'] = operation
                    attack['substitute_operations'] = deepcopy(non_specified_operation)
                    attack['check_rule'] = "Defined HTTP endpoints property's value is not 'all'" \
                                           "AND Identifiers used in operation is not 'zero'"
                    attack['description'] = "Request's verb is changed to other verb that is not specified in " \
                                            "endpoint's description. Incorrect behavior is when authorization checks " \
                                            "are performed over described verbs and verb transformation is performed " \
                                            "after authorization check "
                    if self.attack_spec.get(path) is None:
                        self.attack_spec[path] = []
                    self.attack_spec[path].append(attack)

    def __verb_tampering_parameters_exchange(self, path, content):
        """Check for verb tampering attack: operation uses parameters from other operation
        path - endpoint's path (OpenAPI PATH object)
        content - endpoint's content"""
        if [endpoint_property
            for endpoint_property in content.get('endpoint_level_properties')
                if endpoint_property['name'] == 'defined_http_verbs'][0] != 'Single':
            defined_operations = [operation for operation in self.operations if content.get(operation) is not None]
            for index, operation in enumerate(defined_operations):
                for operation2 in defined_operations[index + 1:]:
                    operation_content = content.get(operation)
                    operation2_content = content.get(operation2)
                    operation_parameters_property = self.__extract_property(operation_content,
                                                                            'method_level_properties',
                                                                            'operation parameters list')
                    operation2_parameters_property = self.__extract_property(operation2_content,
                                                                             'method_level_properties',
                                                                             'operation parameters list')
                    if operation_parameters_property['value'] != 'empty' \
                            or operation2_parameters_property['value'] != 'empty':
                        operation_identifiers = self.__extract_property(operation_content,
                                                                        'method_level_properties',
                                                                        'identifiers used in operation')
                        operation2_identifiers = self.__extract_property(operation2_content,
                                                                         'method_level_properties',
                                                                         'identifiers used in operation')
                        # ToDo: implement parameters list euqality (only non-emptiness is checked)
                        if operation_identifiers != 'zero' or operation2_identifiers != 'zero':
                            attack = deepcopy(self.attack_structure_example)
                            attack['name'] = 'Adding parameters used in other HTTP Methods'
                            attack['type'] = 'Endpoint verb tampering'
                            attack['target_operation'] = operation
                            attack['target_parameters_from_operation'] = operation2
                            attack['check_rule'] = "Defined HTTP endpoints property's value IS NOT single AND " \
                                                   "Operations' parameters list are not same or empty "
                            attack['description'] = "Authorization may be performed for a concrete verb and its " \
                                                    "parameters but service logic ignores requests verb "
                            if self.attack_spec.get(path) is None:
                                self.attack_spec[path] = []
                            self.attack_spec[path].append(attack)
                            attack2 = deepcopy(attack)
                            attack2['target_operation'] = operation2
                            attack2['target_parameters_from_operation'] = operation
                            self.attack_spec[path].append(attack2)

    @staticmethod
    def __extract_property(content, level, property_name):
        """content - object that contains <>_level_properties, e.g. endpoint_level_properties, etc.
        level - key, e.g. endpoint_level_properties, method_level_properties, parameter_level_properties
        property_name - 'name' key of property's object to find"""
        found_properties = [requested_property for requested_property in content[level]
                            if requested_property['name'] == property_name]
        if found_properties is None or len(found_properties) != 1:
            raise RuntimeError("Requested property is not found or ambiguous")

        return found_properties[0]

    def save_output(self, savepath):
        with open(savepath, 'w') as file:
            yaml.safe_dump(self.attack_spec, file, sort_keys=False)
