import yaml


# ToDo: Move property names to distinct namespace and use internal constant corresponding ids instead
class OpenAPISpecAnnotator:
    def __init__(self):
        self.spec = None
        self.bola_spec = None
        # Set of operations OpenAPI 3.0 specifications supports (HTTP 1.1 specifies 'connect' method)
        self.operations = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']
        self.defined_verbs_property_options = {
            1: 'Single',
            len(self.operations): 'All',
        }

    def parse_spec(self, filename):
        """Public method to invoke OpenAPI 3.0 specification processing to annotate with BOLA/IDOR properties.
        Use save_spec(savepath) to save processed specification
        """
        try:
            f = open(filename, 'r')
        except OSError:
            print("Could not open/read file", filename)
            exit(2)
        self.spec = yaml.load(f, Loader=yaml.SafeLoader)
        self.bola_spec = self.spec.copy()

        for key, value in self.spec.items():
            if key.startswith('/'):
                print("Endpoint found:", key)
                self.__parse_endpoint(key, value)

    # ToDo: rename content to description or any better synonym
    def __parse_endpoint(self, path, content):
        content: dict
        # Endpoint parameter properties processing
        if content.get('parameters') is not None:
            modified_parameters = self.__analyze_parameters(content.get('parameters'))
            content['parameters'] = modified_parameters
        # Endpoint level properties processing part
        endpoint_level_properties = []
        # Defined HTTP verbs property
        found_operations = [operation for operation in self.operations if content.get(operation)]
        defined_verbs_property = {'name': 'defined_http_verbs',
                                  'value': self.defined_verbs_property_options.get(len(found_operations),
                                                                                   'Multiple')
                                  }
        endpoint_level_properties.append(defined_verbs_property)
        content['endpoint_level_properties'] = endpoint_level_properties
        for operation in found_operations:
            modified_operation = self.__analyze_operation(operation, content.get(operation), content.get('parameters'))
            content[operation] = modified_operation
        self.bola_spec[path] = content

    def __analyze_parameters(self, parameters):
        parameters: list
        modified_parameters = []
        for i, parameter in enumerate(parameters):
            parameter_level_properties = self.__analyze_parameter(parameter)
            if len(parameter_level_properties):
                parameter: dict
                parameter['parameter_level_properties'] = parameter_level_properties
            modified_parameters.append(parameter)
        return modified_parameters

    def __analyze_parameter(self, parameter):
        """Currently parameter_level_properties is a list but should changed to dictionary
        for better visibility and working with its attributes, e.g. is identifier"""
        parameter_level_properties = []
        is_identifier = None
        parameter: dict
        if parameter.get('type') is not None:
            if parameter['type'] == 'integer':
                is_identifier = True
                parameter_level_properties.append({'name': 'identifier', 'value': True})
        if is_identifier:
            parameter_level_properties.append({'name': 'parameter location', 'value': parameter['in']})
            parameter_level_properties.append({'name': 'parameter type', 'value': parameter['type']})
        return parameter_level_properties

    def __analyze_operation(self, operation, content, endpoint_parameters=None):
        method_level_properties = []
        # Operation parameters
        operation_parameters_defined = 'non-empty' if content.get('parameters') is not None else 'empty'
        method_level_properties.append({'name': 'operation parameters list',
                                        'value': operation_parameters_defined})
        # Annotate operation parameters (do it first may be)
        if content.get('parameters') is not None:
            modified_parameters = self.__analyze_parameters(content.get('parameters'))
            content['parameters'] = modified_parameters
        # Number of identifiers targeted/affected
        # Make a check for endpoint + operation parameters which one are identifiers
        operation_identifiers_count = 0
        # ToDo: rewrite it to more Python style
        if endpoint_parameters is not None:
            for parameter in endpoint_parameters:
                properties = parameter.get('parameter_level_properties')
                if properties is not None:
                    for parameter_property in properties:
                        if parameter_property['name'] == 'identifier' and parameter_property['value'] is True:
                            operation_identifiers_count += 1
        if content.get('parameters') is not None:
            for parameter in content.get('parameters'):
                properties = parameter.get('parameter_level_properties')
                if properties is not None:
                    for parameter_property in properties:
                        if parameter_property['name'] == 'identifier' and parameter_property['value'] is True:
                            operation_identifiers_count += 1
        method_level_properties.append({'name': 'identifiers used in operation',
                                        'value': {0: 'zero',
                                                  1: 'single'}.get(operation_identifiers_count, 'multiple')})
        # ToDo: prototype pollution check
        # Authorization required check. No propagation of security field
        # from endpoint or specification level implemented
        content: dict
        authorization_required = False
        if content.get('security') is not None:
            authorization_required = True if len(content.get('security')) > 0 else False
        method_level_properties.append({'name': 'authorization required',
                                        'value': authorization_required})
        content['method_level_properties'] = method_level_properties
        return content

    def save_spec(self, savepath):
        with open(savepath, 'w') as file:
            yaml.safe_dump(self.bola_spec, file, sort_keys=False)
