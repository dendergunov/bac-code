import yaml


# ToDo: Move property names to distinct namespace and use internal constant corresponding ids instead
# ToDo: Add parsers for requestBody, components and schema objects
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
        self.paths_found = 0
        self.authorization_specified = False

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

    def __parse_endpoint(self, path, path_schema):
        path_schema: dict
        # Endpoint parameter properties processing
        if path_schema.get('parameters') is not None:
            modified_parameters = self.__analyze_parameters(path_schema.get('parameters'))
            path_schema['parameters'] = modified_parameters

        endpoint_authorization = self.authorization_specified
        if path_schema.get('security') is not None:
            endpoint_authorization = True if len(path_schema['security']) > 0 else False

        found_operations = [operation for operation in self.operations if path_schema.get(operation)]
        # Method level parameter complement
        for operation in found_operations:
            modified_operation = self.__analyze_operation(operation, path_schema.get(operation),
                                                          path_schema.get('parameters'), endpoint_authorization)
            path_schema[operation] = modified_operation

        # Endpoint level properties complement
        # Defined HTTP verbs property
        endpoint_level_properties = {
            'defined_http_verbs': self.defined_verbs_property_options.get(len(found_operations),
                                                                          'Multiple')}
        path_schema['endpoint_level_properties'] = endpoint_level_properties
        self.bola_spec['paths'][path] = path_schema

    def __analyze_parameters(self, parameters_list):
        """Private method is invoked with a list of parameters (described at endpoint or method level) passed
        to iteratively complement properties of every parameter in the list"""
        parameters_list: list
        modified_parameters = []
        for i, parameter_schema in enumerate(parameters_list):
            parameter_level_properties = self.__analyze_parameter(parameter_schema)
            if len(parameter_level_properties):
                parameter_schema: dict
                parameter_schema['parameter_level_properties'] = parameter_level_properties
            modified_parameters.append(parameter_schema)
        return modified_parameters

    def __analyze_parameter(self, parameter_schema):
        """Private method is invoked with a parameter schema passed. Returns a copy of the parameter schemas passed
        with parameter_level_properties dictionary inserted with the 'parameter_level_properties' key"""
        # ToDo: add reference resolving
        parameter_level_properties = {}
        is_identifier = False
        parameter_type = None
        parameter_schema: dict
        schema_field = parameter_schema.get('schema')
        if schema_field is not None:
            if schema_field.get('type') is not None:
                # ToDo: Add more checks on parameter being an identifier
                if schema_field['type'] == 'integer':
                    parameter_type = 'integer'
                if schema_field['type'] == 'array':
                    parameter_type = 'array'
                    if schema_field.get('items').get('type') == 'integer':
                        is_identifier = True
                if parameter_schema['name'].lower() == "id" or parameter_schema['name'].lower().endswith("_id") \
                        or parameter_schema['name'].endswith("Id") or parameter_schema['name'].endswith("ID"):
                    is_identifier = True
                if parameter_schema['name'].lower() == "uuid" or parameter_schema['name'].lower().endswith("uuid"):
                    is_identifier = True
                    parameter_type = 'UUID'
                # ToDo: add checks for personal information type
            # ToDo: add parsing of complex objects
        parameter_level_properties['is_identifier'] = is_identifier

        # ToDo: Add check for $ref schema
        if is_identifier:
            parameter_level_properties['location'] = parameter_schema['in']
            parameter_level_properties['type'] = parameter_type if parameter_type is not None else schema_field['type']
        return parameter_level_properties

    def __analyze_operation(self, operation, operation_schema, endpoint_parameters=None, endpoint_authorization=False):
        method_level_properties = {}
        # Operation parameters
        operation_parameters_defined = True if operation_schema.get('parameters') is not None else False
        method_level_properties['operation_only_parameters_specified'] = operation_parameters_defined

        # Operation uses parameters
        method_level_properties['parameters_required'] = False if endpoint_parameters is None else True
        if operation_schema.get('parameters') is not None:
            method_level_properties['parameters_required'] = True

        # Operation has body
        method_level_properties['has_body'] = True if operation_schema.get('requestBody') is not None else False

        # Annotate operation parameters (do it first may be)
        if operation_schema.get('parameters') is not None:
            modified_parameters = self.__analyze_parameters(operation_schema.get('parameters'))
            operation_schema['parameters'] = modified_parameters

        # Number of identifiers targeted/affected property:
        # Make a check for endpoint + operation parameters which one are identifiers
        operation_identifiers_count = 0
        if endpoint_parameters is not None:
            for parameter in endpoint_parameters:
                # Every parameter has 'parameter_level_properties' field to this moment
                properties = parameter.get('parameter_level_properties')
                if properties['is_identifier']:
                    operation_identifiers_count += 1
        if operation_schema.get('parameters') is not None:
            for parameter in operation_schema.get('parameters'):
                properties = parameter.get('parameter_level_properties')
                if properties['is_identifier']:
                    operation_identifiers_count += 1
        method_level_properties['identifiers_used'] = {0: 'zero',
                                                       1: 'single'}.get(operation_identifiers_count, 'multiple')
        # Authorization required check.
        operation_schema: dict
        authorization_required = endpoint_authorization
        if operation_schema.get('security') is not None:
            authorization_required = True if len(operation_schema.get('security')) > 0 else False
        method_level_properties['authorization_required'] = authorization_required

        operation_schema['method_level_properties'] = method_level_properties
        return operation_schema

    def save_spec(self, savepath):
        with open(savepath, 'w') as file:
            yaml.safe_dump(self.bola_spec, file, sort_keys=False)
