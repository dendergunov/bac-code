from copy import deepcopy

operations = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']


class EndpointAttackAnalyzer:
    def __init__(self, path, content):
        self.path = path
        self.content = content
        self.attack_spec = []
        self.attack_structure_example = {
            'name': '',
            'type': '',
            'check_rule': '',
            'description': '',
            'examples': []
        }

    def parse_endpoint(self):
        # Call attack checker methods
        content: dict
        self.__authorization_token_manipulation()
        self.__verb_tampering_non_specified()
        self.__verb_tampering_parameters_exchange()
        self.__enumeration()

    @staticmethod
    def __extract_property(content, level, property_name):
        """content - object that contains <>_level_properties, e.g. endpoint_level_properties, etc.
        level - key, e.g. endpoint_level_properties, method_level_properties, parameter_level_properties
        property_name - 'name' key of property's object to find"""
        found_properties = [requested_property for requested_property in content[level]
                            if requested_property['name'] == property_name]
        if found_properties is None:
            return None
        if len(found_properties) != 1:
            raise RuntimeError("Requested property is not found or ambiguous")
        return found_properties[0]

    def __authorization_token_manipulation(self):
        """path - endpoint's path (OpenAPI PATH object)
        content - endpoint's content"""
        content: dict
        target_operations = []
        for operation in operations:
            if self.content.get(operation) is not None:
                operation_content = self.content.get(operation)
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
            self.attack_spec.append(attack)

    def __verb_tampering_non_specified(self):
        """Check for verb tampering attack: operation is changed to one without definition in specification
        path - endpoint's path (OpenAPI PATH object)
        content - endpoint's content"""
        content: dict
        non_specified_operation = [operation for operation in operations if self.content.get(operation) is None]
        for operation in operations:
            if self.content.get(operation) is not None:
                identifiers_used = self.__extract_property(self.content.get(operation), 'method_level_properties',
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
                    self.attack_spec.append(attack)

    def __verb_tampering_parameters_exchange(self):
        """Check for verb tampering attack: operation uses parameters from other operation
        path - endpoint's path (OpenAPI PATH object)
        content - endpoint's content"""
        if [endpoint_property
            for endpoint_property in self.content.get('endpoint_level_properties')
                if endpoint_property['name'] == 'defined_http_verbs'][0] != 'Single':
            defined_operations = [operation for operation in operations if self.content.get(operation) is not None]
            for index, operation in enumerate(defined_operations):
                for operation2 in defined_operations[index + 1:]:
                    operation_content = self.content.get(operation)
                    operation2_content = self.content.get(operation2)
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
                        # ToDo: implement parameters list equality (only non-emptiness is checked)
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
                            self.attack_spec.append(attack)
                            attack2 = deepcopy(attack)
                            attack2['target_operation'] = operation2
                            attack2['target_parameters_from_operation'] = operation
                            self.attack_spec.append(attack2)

    def __enumeration(self):
        """Check for verb tampering attack: operation uses parameters from other operation
                path - endpoint's path (OpenAPI PATH object)
                content - endpoint's content"""
        # Check each operation
        # if operation uses authorization
        # for each parameter identifier (endpoint_level + operation_level)
        # decide black box or gray box
        specified_operations = [operation for operation in operations if self.content.get(operation) is not None]
        for operation in specified_operations:
            if self.__extract_property(self.content.get(operation),
                                       'method_level_properties',
                                       'identifiers used in operation')['value'] != 'zero':
                endpoint_parameters = self.content.get('parameters')
                if endpoint_parameters is not None:
                    for parameter in endpoint_parameters:
                        identifier_property = self.__extract_property(parameter,
                                                                      'parameter_level_properties',
                                                                      'identifier')
                        if identifier_property['value'] is True:
                            # ToDo: Add check and property for simple identifier or UUID/etc. to distinguish between
                            #  enumeration with and without knowledge (black/gray box)
                            attack = deepcopy(self.attack_structure_example)
                            attack['name'] = 'Enumeration without a priori knowledge'
                            attack['type'] = 'Enumeration'
                            attack['target_operation'] = operation
                            attack['check_rule'] = "Number of identifiers/parameters targeted/affected is NOT zero " \
                                                   "AND operation uses authorization "
                            attack['description'] = "Identifier is tampered for enumeration based on automatically " \
                                                    "or semi-automatically determined pattern. In the simplest form, " \
                                                    "identifier is sequential and enumeration leads to targeting " \
                                                    "existing object with identifier being unknown at the start "
                            variations = [
                                {'name': 'Same identifier pattern enumeration',
                                 'description': 'Identifier is not decorated',
                                 'example': []},
                                {'name': 'File extension decoration',
                                 'description': 'Identifier is decorated with file extension',
                                 'example': []},
                                {'name': 'Wildcard replacement',
                                 'description': 'Identifier is replaced by wildcard',
                                 'example': []},
                                {'name': 'Wildcard appending',
                                 'description': 'Identifier value is appended with a special '
                                                'character, e.g. %',
                                 'example': []}]
                            attack['variations'] = deepcopy(variations)
                            attack['target_parameter'] = deepcopy(parameter)
                            self.attack_spec.append(attack)
