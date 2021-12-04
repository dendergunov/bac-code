import yaml
from os.path import commonprefix
from identifier import *
from endpoint import operations
from property import *


# ToDo: Add parsers for requestBody, components and schema objects
class OpenAPISpecAnnotator:
    def __init__(self):
        self.spec = None
        self.bola_spec = None
        self.authorization_specified = False
        # attributes for statistic storage
        self.paths_found = 0
        self.methods_found = 0
        self.identifiers_found = 0
        self.parameters_dict = dict()
        self.identifiers_dict = dict()
        self.no_identifiers_dict = dict()

    def parse_spec(self, filename):
        """Public method to invoke OpenAPI 3.0 specification processing to annotate with Broken Access Control
        properties. Use save_spec(savepath) to save processed specification
        """
        try:
            f = open(filename, 'r')
            self.spec = yaml.load(f, Loader=yaml.SafeLoader)
            self.bola_spec = self.spec.copy()

            if self.spec.get('security') is not None:
                self.authorization_specified = True if len(self.spec['security']) > 0 else False

            if self.spec.get('paths') is not None:
                print("Paths OpenAPI object found!")
                for path, path_schema in self.spec.get('paths').items():
                    if path.startswith('/'):
                        print("Endpoint found:", path)
                        self.__parse_endpoint(path, path_schema)
                        self.paths_found += 1
            print("Total paths processed:", self.paths_found)
            self.identifiers_dict = {key: value for key, value in self.parameters_dict.items() if key[2] is True}
            self.no_identifiers_dict = {key: value for key, value in self.parameters_dict.items() if key[2] is False}
            f.close()
        except OSError:
            print("Could not open/read file", filename)
            exit(2)

    def __parse_endpoint(self, path, path_schema):
        path_schema: dict
        # Endpoint parameter properties processing
        if path_schema.get('parameters') is not None:
            modified_parameters = self.__analyze_parameters(path_schema.get('parameters'), path)
            path_schema['parameters'] = modified_parameters

        endpoint_authorization = self.authorization_specified
        if path_schema.get('security') is not None:
            endpoint_authorization = True if len(path_schema['security']) > 0 else False

        found_operations = [operation for operation in operations if path_schema.get(operation)]
        # Method level parameter complement
        for operation in found_operations:
            modified_operation = self.__analyze_operation(operation, path_schema.get(operation),
                                                          path_schema.get('parameters'), endpoint_authorization, path)
            path_schema[operation] = modified_operation
            self.methods_found += 1

        # Endpoint level properties complement
        # Defined HTTP verbs property
        endpoint_level_properties = {
            EndpointProperties.VERBS_DEFINED: verbs_defined.get(len(found_operations))}
        path_schema['endpoint_level_properties'] = endpoint_level_properties
        self.bola_spec['paths'][path] = path_schema

    def __analyze_parameters(self, parameters_list, path=None):
        """Private method is invoked with a list of parameters (described at endpoint or method level) passed
        to iteratively complement properties of every parameter in the list"""
        parameters_list: list
        modified_parameters = []
        for i, parameter_schema in enumerate(parameters_list):
            parameter_level_properties = self.__analyze_parameter(parameter_schema, path)
            if len(parameter_level_properties):
                parameter_schema: dict
                parameter_schema['parameter_level_properties'] = parameter_level_properties
            modified_parameters.append(parameter_schema)
        return modified_parameters

    def __analyze_parameter(self, parameter_schema, path=None):
        """Private method is invoked with a parameter schema passed. Returns a copy of the parameter schemas passed
        with parameter_level_properties dictionary inserted with the 'parameter_level_properties' key"""
        parameter_level_properties = {}
        is_identifier = False
        parameter_type = None
        parameter_schema: dict
        schema_field = parameter_schema.get('schema')
        if schema_field is not None:
            # ToDo: add reference resolving
            if schema_field.get('$ref') is not None:
                print('Parameter', parameter_schema['name'], 'schema is unresolved')
            else:
                # Heuristic rules for identifier detection
                # Based on parameter's name
                if parameter_schema['name'].lower() == "id" or parameter_schema['name'].lower().endswith("_id") \
                        or parameter_schema['name'].endswith("Id") or parameter_schema['name'].endswith("ID") \
                        or parameter_schema['name'].lower() == "pid":
                    is_identifier = True
                if parameter_schema['name'].lower().endswith('name'):
                    is_identifier = True
                if parameter_schema['name'].lower() == "uuid" or parameter_schema['name'].lower().endswith("uuid") or \
                   parameter_schema['name'].lower() == "guid" or parameter_schema['name'].lower().endswith("guid"):
                    is_identifier = True
                # Dictionary check
                if parameter_schema['name'] in identifier_names:
                    is_identifier = True

                # Path-based check
                if parameter_schema['in'] == 'path' and is_identifier is False:
                    if path is not None:
                        substrings = path.split('/')
                        try:
                            location = substrings.index(''.join(['{', parameter_schema['name'], '}']))
                            # At the start of path check
                            if location == 0:
                                is_identifier = True
                            else:
                                # Preceding substring check
                                preceding_string = substrings[location - 1]
                                prefix = commonprefix([parameter_schema['name'].lower(), preceding_string.lower()])
                                if 1 < len(preceding_string) - 3 <= len(prefix):
                                    is_identifier = True
                                # Preceding substring + verb check
                                if location > 1:
                                    preceding_string = substrings[location - 2]
                                    prefix = commonprefix([parameter_schema['name'].lower(), preceding_string.lower()])
                                    if 1 < len(preceding_string) - 3 <= len(prefix):
                                        is_identifier = True
                        except ValueError:
                            None

                # ToDo: Add description and tags checks
                # ToDo: Add producer/consumer check

        parameter_level_properties[ParameterProperties.IS_IDENTIFIER] = is_identifier
        if is_identifier:
            # Type identification
            if schema_field.get('type') is not None:
                if schema_field['type'] == 'integer':
                    parameter_type = IdentifierType.INTEGER
                if schema_field['type'] == 'array':
                    parameter_type = IdentifierType.LIST
                if parameter_schema['name'].lower() == "uuid" or parameter_schema['name'].lower().endswith("uuid") or \
                   parameter_schema['name'].lower() == "guid" or parameter_schema['name'].lower().endswith("guid"):
                    parameter_type = IdentifierType.UUID
                if parameter_schema['name'].lower() in personal_identifiers:
                    parameter_type = IdentifierType.PERSONAL
                if parameter_type is None and schema_field['type'] == 'string':
                    parameter_type = IdentifierType.STRING
            else:
                # ToDo: add parsing of complex objects
                parameter_type == IdentifierType.OBJECT
            if parameter_type is None:
                parameter_type = IdentifierType.OTHER

            # Filename check rule
            is_filename = False
            if parameter_schema['name'].lower() == 'file' or parameter_schema['name'].lower() == 'filename':
                is_filename = True
            if parameter_schema['in'] == 'path':
                substrings = path.split('/')
                decorated_name = ''.join(['{', parameter_schema['name'], '}'])
                for substr in substrings:
                    if decorated_name in substr:
                        if decorated_name != substr and '.' in substr:
                            if substr.index('.') > substr.index(decorated_name):
                                is_filename = True
            parameter_level_properties[ParameterProperties.IS_FILENAME] = is_filename

            # Identifier properties
            parameter_level_properties[ParameterProperties.LOCATION] = parameter_schema['in']
            parameter_level_properties[ParameterProperties.TYPE] = \
                parameter_type if parameter_type is not None else schema_field['type']
            self.identifiers_found += 1

        # Fill up unique parameters dictionary
        if self.parameters_dict.get((parameter_schema['name'], parameter_schema['in'], is_identifier)) is not None:
            self.parameters_dict[(parameter_schema['name'], parameter_schema['in'], is_identifier)] += 1
        else:
            self.parameters_dict[(parameter_schema['name'], parameter_schema['in'], is_identifier)] = 1
        return parameter_level_properties

    def __analyze_operation(self, operation, operation_schema, endpoint_parameters=None,
                            endpoint_authorization=False, path=None):
        method_level_properties = {}
        # Operation parameters
        operation_parameters_defined = True if operation_schema.get('parameters') is not None else False
        method_level_properties[MethodProperties.OPERATION_PARAMETERS_DEFINED] = operation_parameters_defined

        # Operation uses parameters
        method_level_properties[
            MethodProperties.PARAMETERS_REQUIRED] = False if endpoint_parameters is None else True
        if operation_schema.get('parameters') is not None:
            method_level_properties[MethodProperties.PARAMETERS_REQUIRED] = True

        # Operation has body
        method_level_properties[MethodProperties.HAS_BODY] = \
            True if operation_schema.get('requestBody') is not None else False

        # Annotate operation parameters (do it first may be)
        if operation_schema.get('parameters') is not None:
            modified_parameters = self.__analyze_parameters(operation_schema.get('parameters'), path)
            operation_schema['parameters'] = modified_parameters

        # Number of identifiers targeted/affected property:
        # Make a check for endpoint + operation parameters which one are identifiers
        operation_identifiers_count = 0
        if endpoint_parameters is not None:
            for parameter in endpoint_parameters:
                # Every parameter has 'parameter_level_properties' field to this moment
                properties = parameter.get('parameter_level_properties')
                if properties[ParameterProperties.IS_IDENTIFIER]:
                    operation_identifiers_count += 1
        if operation_schema.get('parameters') is not None:
            for parameter in operation_schema.get('parameters'):
                properties = parameter.get('parameter_level_properties')
                if properties[ParameterProperties.IS_IDENTIFIER]:
                    operation_identifiers_count += 1
        method_level_properties[MethodProperties.IDENTIFIERS_USED] = {0: 'zero',
                                                                      1: 'single'}.get(operation_identifiers_count,
                                                                                       'multiple')
        # Authorization required check.
        operation_schema: dict
        authorization_required = endpoint_authorization
        if operation_schema.get('security') is not None:
            authorization_required = True if len(operation_schema.get('security')) > 0 else False
        method_level_properties[MethodProperties.AUTHORIZATION_REQUIRED] = authorization_required

        operation_schema['method_level_properties'] = method_level_properties
        return operation_schema

    def save_spec(self, savepath):
        with open(savepath, 'w') as file:
            yaml.safe_dump(self.bola_spec, file, sort_keys=False)
        file.close()
