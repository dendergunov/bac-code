from copy import deepcopy
from typing import Dict, List, Any, Union
import attack_technique


operations = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']


class EndpointAttackAnalyzer:
    def __init__(self, path, path_schema):
        self.path = path
        self.path_schema = path_schema
        self.attack_spec = []
        self.attack_structure_example = {
            'name': '',
            'check_rule': '',
            'description': '',
            'examples': [],
        }
        self.attack_proposed = 0
        self.attacks_count_dict = {attack_technique.enum_black_box: 0,
                                   attack_technique.enum_gray_box: 0,
                                   attack_technique.manipulate_file_extension: 0,
                                   attack_technique.replace_wildcard: 0,
                                   attack_technique.append_list: 0,
                                   attack_technique.tamper_verb_non_spec: 0,
                                   attack_technique.tamper_verb_exchange: 0,
                                   attack_technique.manipulate_auth_data: 0,
                                   attack_technique.parameter_pollution: 0}

    def parse_endpoint(self, **disable_attack_flags):
        # Call attack checker methods
        content: dict
        if disable_attack_flags.get('authorization_token_manipulation_off') is not True:
            self.__authorization_data_manipulation()
        if disable_attack_flags.get('verb_tampering_non_specified_off') is not True:
            self.__verb_tampering_non_specified()
        # ToDo: Rename verb tampering parameters exchange parameters and body
        if disable_attack_flags.get('verb_tampering_parameters_exchange_off') is not True:
            self.__verb_tampering_parameters_exchange()
        if disable_attack_flags.get('enumeration_off') is not True:
            self.__enumeration()
        if disable_attack_flags.get('parameter_pollution_off') is not True:
            self.__parameter_pollution()

    def __authorization_data_manipulation(self):
        """path - endpoint's path (OpenAPI PATH object)
        path_schema - endpoint's content"""
        self.path_schema: dict
        target_operations = []
        for operation in operations:
            if self.path_schema.get(operation) is not None:
                operation_schema = self.path_schema.get(operation)
                if operation_schema.get('method_level_properties') is not None:
                    if operation_schema['method_level_properties']['authorization_required']:
                        target_operations.append(operation)

        if len(target_operations):
            attack = deepcopy(self.attack_structure_example)
            attack['name'] = 'Authorization token manipulation'
            attack['target_operation'] = deepcopy(target_operations)
            attack['check_rule'] = "Endpoint's operation requires authorization"
            attack['description'] = 'Request is repeated with authorization token of another user to check whether ' \
                                    'authorization is incorrect and non-permitted access is granted. Request is ' \
                                    'repeated without authorization token to check whether authorization checks are ' \
                                    'done '
            attack['expected_response'] = {}
            attack['unexpected_response'] = {}
            for operation in target_operations:
                expected_responses = {}
                if self.path_schema[operation]['responses'].get('401') is not None:
                    expected_responses['401'] = self.path_schema[operation]['responses']['401']
                if self.path_schema[operation]['responses'].get('403') is not None:
                    expected_responses['403'] = self.path_schema[operation]['responses']['403']
                unexpected_responses = deepcopy(self.path_schema[operation]['responses'])
                if unexpected_responses.get('401') is not None:
                    unexpected_responses.pop('401')
                if unexpected_responses.get('403') is not None:
                    unexpected_responses.pop('403')
                attack['expected_response'][operation] = expected_responses
                attack['unexpected_response_codes'] = list(unexpected_responses.keys())
            self.attack_proposed += 1
            self.attacks_count_dict[attack_technique.manipulate_auth_data] += 1
            self.attack_spec.append(attack)

    def __verb_tampering_non_specified(self):
        """Check for verb tampering attack: operation is changed to one without definition in specification
        path - endpoint's path (OpenAPI PATH object)
        content - endpoint's content"""
        path_schema: dict
        non_specified_operation = [operation for operation in operations if self.path_schema.get(operation) is None]
        for operation in operations:
            if self.path_schema.get(operation) is not None:
                # ToDo: move back parameters_required, article specifies on identifiers_used
                # parameters_required = self.path_schema[operation]['method_level_properties']['parameters_required']
                # has_body = self.path_schema[operation]['method_level_properties']['has_body']
                parameters_required = self.path_schema[operation]['method_level_properties']['identifiers_used']
                # if parameters_required or has_body:
                if parameters_required != 'zero':
                    attack = deepcopy(self.attack_structure_example)
                    attack['name'] = 'Change HTTP Method (Verb tampering) to non-specified'
                    attack['target_operation'] = operation
                    attack['substitute_operations'] = deepcopy(non_specified_operation)
                    attack['check_rule'] = "Defined HTTP endpoints property's value is not 'all'" \
                                           "AND (operation uses parameters OR has body)"
                    attack['description'] = "Request's verb is changed to other verb that is not specified in " \
                                            "endpoint's description. Incorrect behavior is when authorization checks " \
                                            "are performed over described verbs and verb transformation is performed " \
                                            "after authorization check "
                    attack['expected_response'] = {'405': "Method Not Allowed", '501': "Not Implemented"}
                    unexpected_responses = deepcopy(self.path_schema[operation]['responses'])
                    attack['unexpected_response_codes'] = list(unexpected_responses.keys())
                    self.attack_proposed += 1
                    self.attacks_count_dict[attack_technique.tamper_verb_non_spec] += 1
                    self.attack_spec.append(attack)

    def __verb_tampering_parameters_exchange(self):
        """Check for verb tampering attack: operation uses parameters from other operation
        path - endpoint's path (OpenAPI PATH object)
        content - endpoint's content"""
        if self.path_schema['endpoint_level_properties']['defined_http_verbs'] == 'Single':
            return
        defined_operations = [operation for operation in operations if self.path_schema.get(operation) is not None]
        for sink_operation in defined_operations:
            operations_to_take_their_parameters = []
            for source_operation in defined_operations:
                if sink_operation == source_operation:
                    continue
                sink_operation_schema = self.path_schema.get(sink_operation)
                source_operation_schema = self.path_schema.get(source_operation)
                if sink_operation_schema['method_level_properties'][
                    'operation_only_parameters_specified'] is False and \
                        source_operation_schema['method_level_properties'][
                            'operation_only_parameters_specified'] is False and \
                        sink_operation_schema['method_level_properties']['has_body'] is False and \
                        source_operation_schema['method_level_properties']['has_body']:
                    continue
                sink_operation_parameters = sink_operation_schema.get('parameters')
                source_operation_parameters = source_operation_schema.get('parameters')

                parameters_are_same = True
                bodies_are_same = True
                if (sink_operation_parameters is None) or (source_operation_parameters is None):
                    parameters_are_same = False
                else:
                    if len(sink_operation_parameters) == len(source_operation_parameters):
                        sink_operation_parameters = sorted(sink_operation_parameters, key=lambda x: x['name'])
                        source_operation_parameters = sorted(source_operation_parameters, key=lambda x: x['name'])
                        for i, parameter in enumerate(sink_operation_parameters):
                            if parameter['name'] != source_operation_parameters[i]['name']:
                                parameters_are_same = False
                                break
                            if parameter['schema']['type'] != source_operation_parameters[i]['schema']['type']:
                                parameters_are_same = False
                                break
                    if len(sink_operation_parameters) != len(source_operation_parameters):
                        parameters_are_same = False
                if sink_operation_schema.get('requestBody') != source_operation_schema.get('requestBody'):
                    bodies_are_same = False
                if parameters_are_same is False or bodies_are_same is False:
                    if sink_operation_parameters is not None:
                        operations_to_take_their_parameters.append(source_operation)
            if len(operations_to_take_their_parameters) == 0:
                continue
            attack = deepcopy(self.attack_structure_example)
            attack['name'] = 'Adding parameters and body used in another HTTP Methods'
            attack['sink_operation'] = sink_operation
            attack['source_operations'] = operations_to_take_their_parameters
            attack['check_rule'] = "Defined HTTP endpoints property's value IS NOT single AND " \
                                   "Operations require parameters AND (operation-specific parameter lists are not " \
                                   "same AND request bodies are not same) AND one of operations (require parameters " \
                                   "OR has body) "
            attack['description'] = "Authorization may be performed for a concrete verb and its " \
                                    "parameters but service logic ignores requests verb "
            unexpected_responses = deepcopy(self.path_schema[sink_operation]['responses'])
            if unexpected_responses.get('400') is not None:
                attack['expected_response'] = unexpected_responses.pop('400')
            else:
                attack['expected_response'] = {'400': "Bad Request"}
            attack['unexpected_response_codes'] = list(unexpected_responses.keys())
            self.attack_proposed += 1
            self.attacks_count_dict[attack_technique.tamper_verb_exchange] += 1
            self.attack_spec.append(attack)

    def __enumeration(self):
        """Check for verb tampering attack: operation uses parameters from other operation
                path - endpoint's path (OpenAPI PATH object)
                content - endpoint's content"""
        endpoint_parameters = self.path_schema.get('parameters', [])
        defined_operations = [operation for operation in operations if self.path_schema.get(operation) is not None]
        for operation in defined_operations:
            if not self.path_schema[operation]['method_level_properties']['parameters_required']:
                continue
            if self.path_schema[operation]['method_level_properties']['identifiers_used'] == 'zero':
                continue
            merged_identifiers_list = list(filter(lambda x: x['parameter_level_properties']['is_identifier'],
                                                  endpoint_parameters + self.path_schema[operation].get('parameters',
                                                                                                        [])))
            # Single parameter enumeration
            # ToDo: Add check for parameters with equal names (should have different keys)
            attack = deepcopy(self.attack_structure_example)
            attack['name'] = 'Enumeration'
            attack['description'] = "Identifier is tampered for enumeration based on automatically " \
                                    "or semi-automatically determined pattern. In the simplest form, " \
                                    "identifier is sequential and enumeration leads to targeting " \
                                    "existing object with identifier being unknown at the start "
            attack['target_operation'] = operation
            attack['targeted_parameters'] = {}
            attack['check_rule'] = "Operation uses parameters AND operation has parameters identifiers"
            for identifier in merged_identifiers_list:
                # Check for simple enumeration if type is integer
                description = dict()
                if identifier['parameter_level_properties']['type'] == 'integer':
                    description['attacks'] = ["Enumeration without a priori knowledge"]
                    description['parameter_level_properties'] = identifier['parameter_level_properties']
                    description['additional_check_rule'] = "Identifier's type is integer AND Authorization is required"
                    attack['targeted_parameters'][identifier['name']] = description
                    self.attacks_count_dict[attack_technique.enum_black_box] += 1
                    print('Simple enumeration')
                    continue

                if identifier['parameter_level_properties']['type'] == 'array':
                    description['attacks'] = ["Non-owned object's identifier appending to the end of a list"]
                    description['parameter_level_properties'] = identifier['parameter_level_properties']
                    description[
                        'additional_check_rule'] = "Authorization is required AND Parameter's type is array"
                    self.attacks_count_dict[attack_technique.append_list] += 1
                    print('Identifier appending to the end')
                    if identifier['schema']['items']['type'] == 'integer':
                        self.attacks_count_dict[attack_technique.enum_black_box] += 1
                        description['attacks'].append("Enumeration without a priori knowledge")
                        description[
                            'additional_check_rule'] = "Parameter's type is array AND parameter's item's type is " \
                                                       "integer AND Authorization is required "
                        self.attacks_count_dict[attack_technique.enum_black_box] += 1
                        print('Simple enumeration')
                    attack['targeted_parameters'][identifier['name']] = description
                    continue

                # ToDo: Add case-insensitivity for parameter names
                # ToDo: Add GUID check
                if identifier['parameter_level_properties']['type'] == 'UUID':
                    description['attacks'] = ["Enumeration with a priori knowledge"]
                    description['403_response_code_specified'] = True if self.path_schema[operation]['responses'] \
                        .get('403') else False
                    description['parameter_level_properties'] = identifier['parameter_level_properties']
                    description[
                        'additional_check_rule'] = "Identifier's type is UUID"
                    attack['targeted_parameters'][identifier['name']] = description
                    self.attacks_count_dict[attack_technique.enum_gray_box] += 1
                    continue

                # ToDo: Add for other identifiers
                description['attacks'] = ["Enumeration with a priori knowledge"]
                description['additional_check_rule'] = "Authorization is required"

                # ToDo: Add file extension check in path
                if identifier['parameter_level_properties']['type'] == 'string':
                    description['attacks'].append("File extension decoration")
                    description['attacks'].append("Wildcard replacement")
                    description['additional_check_rule'] += ' '.join([description['additional_check_rule'],
                                                                      "AND identifier's type is string"])
                    self.attacks_count_dict[attack_technique.replace_wildcard] += 1
                    self.attacks_count_dict[attack_technique.manipulate_file_extension] += 1
                attack['targeted_parameters'][identifier['name']] = description
                self.attacks_count_dict[attack_technique.enum_gray_box] += 1
            unexpected_responses = deepcopy(self.path_schema[operation]['responses'])
            if unexpected_responses.get('400') is not None:
                attack['expected_response'] = unexpected_responses.pop('400')
            else:
                attack['expected_response'] = {'400': "Bad Request"}
            if unexpected_responses.get('403') is not None:
                attack['expected_response'] = unexpected_responses.pop('403')
            else:
                attack['expected_response'] = {'403': "Forbidden"}
            attack['unexpected_response_codes'] = list(unexpected_responses.keys())
            self.attack_proposed += 1
            self.attack_spec.append(attack)

    def __parameter_pollution(self):
        """Check for parameter pollution attack: one parameter name in multiple parameter places"""
        # Get list of endpoint parameters, get list of operation parameters, merge, sort, check by names
        endpoint_parameters = self.path_schema.get('parameters', [])
        defined_operations = [operation for operation in operations if self.path_schema.get(operation) is not None]
        for operation in defined_operations:
            if not self.path_schema[operation]['method_level_properties']['parameters_required']:
                continue
            merged_parameters_list = endpoint_parameters + self.path_schema[operation].get('parameters', [])
            if len(merged_parameters_list) == 0:
                continue
            sorted_parameters_list = sorted(merged_parameters_list, key=lambda x: x['name'])
            for i, parameter in enumerate(sorted_parameters_list[:-1]):
                # ToDo: add other checks for parameter equivalence
                if parameter['name'] != sorted_parameters_list[i + 1]['name']:
                    continue
                attack = deepcopy(self.attack_structure_example)
                attack['name'] = 'Parameter pollution'
                attack['target_operation'] = operation
                attack['check_rule'] = "Operation uses authorization AND Operation requires parameters AND operation " \
                                       "requires two parameters with same names in different places "
                attack['description'] = "Information in one request is processed and sent into different processing " \
                                        "units of server. Tampering with one of parameter's value is a way to check " \
                                        "that authorization is consistent and there's no case that value from one " \
                                        "location is used for authorization and value from another is used to access " \
                                        "an object "
                attack['target_parameters'] = [parameter, sorted_parameters_list[i + 1]]
                unexpected_responses = deepcopy(self.path_schema[operation]['responses'])
                if unexpected_responses.get('400') is not None:
                    attack['expected_response'] = unexpected_responses.pop('400')
                else:
                    attack['expected_response'] = {'400': "Bad Request"}
                if unexpected_responses.get('422') is not None:
                    attack['expected_response'] = unexpected_responses.pop('422')
                else:
                    attack['expected_response'] = {'422': "Unprocessable Entity"}
                attack['unexpected_response_codes'] = list(unexpected_responses.keys())
                self.attack_proposed += 1
                self.attacks_count_dict[attack_technique.parameter_pollution] += 1
                self.attack_spec.append(attack)
