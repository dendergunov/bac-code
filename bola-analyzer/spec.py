import yaml


class OpenAPISpecAnalyzer:
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
            print(content.get('parameters'))
            modified_parameters = self.__analyze_parameters(content.get('parameters'))
            print(modified_parameters)
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
        self.bola_spec[path] = content

    def __analyze_parameters(self, parameters):
        parameters: list
        modified_parameters = []
        print(parameters)
        for i, parameter in enumerate(parameters):
            print(parameter)
            print(type(parameter))
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
                parameter_level_properties.append({'name': 'identifier', 'value': 'true'})
        if is_identifier:
            parameter_level_properties.append({'name': 'parameter location', 'value': parameter['in']})
            parameter_level_properties.append({'name': 'parameter type', 'value': parameter['type']})
        return parameter_level_properties

    # def __analyze_operation(self, operation, content):

    def save_spec(self, savepath):
        with open(savepath, 'w') as file:
            yaml.safe_dump(self.bola_spec, file, sort_keys=False)
