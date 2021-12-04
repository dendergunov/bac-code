class EndpointProperties:
    VERBS_DEFINED = 'defined_http_verbs'


verbs_defined = {
    0: 'zero',
    1: 'single',
    2: 'multiple',
    3: 'multiple',
    4: 'multiple',
    5: 'multiple',
    6: 'multiple',
    7: 'multiple',
    8: 'all'
}


class MethodProperties:
    HAS_BODY = 'has_body'
    PARAMETERS_REQUIRED = 'parameters_required'
    OPERATION_PARAMETERS_DEFINED = 'operation_only_parameters_specified'
    IDENTIFIERS_USED = 'identifiers_used'
    AUTHORIZATION_REQUIRED = 'authorization_required'


class ParameterProperties:
    IS_IDENTIFIER = 'is_identifier'
    LOCATION = 'location'
    TYPE = 'type'
    IS_FILENAME = 'is_filename'


class IdentifierType:
    INTEGER = 'integer'
    UUID = 'UUID/GUID'
    STRING = 'string'
    PERSONAL = 'personal_information'
    LIST = 'array'
    OBJECT = 'object'
    OTHER = 'other'
