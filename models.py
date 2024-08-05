from neomodel import StructuredNode, StringProperty, DateTimeProperty, UniqueIdProperty, RelationshipTo, RelationshipFrom, StructuredRel, ArrayProperty, FloatProperty, BooleanProperty, IntegerProperty
from datetime import datetime, date
from neomodel import install_labels,db,config

# Set up the connection to your Neo4j database
config.DATABASE_URL = 'bolt://localhost:7687'  # Adjust this to your Neo4j connection URL
config.DATABASE_USER = 'neo4j'  # Your Neo4j username
config.DATABASE_PASSWORD = ''  # Your Neo4j password

'''
    {

  "type": "campaign",

  "spec_version": "2.1",

  "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",

  "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",

  "created": "2016-04-06T20:03:00.000Z",

  "modified": "2016-04-06T20:03:00.000Z",

  "name": "Green Group Attacks Against Finance",

  "description": "Campaign by Green Group against a series of targets in the financial services sector."

}
'''
# what is created by reference in example 
 
class Campaign(StructuredNode):
    uuid=UniqueIdProperty()
    type = StringProperty(default='campaign')#
    name = StringProperty(required=True)
    description = StringProperty()
    references_link = StringProperty()
    objective = StringProperty()
    aliases = StringProperty()
    first_seen = DateTimeProperty()
    last_seen = DateTimeProperty()

    @staticmethod
    def create_campaign(campaign_data):
        campaign = Campaign(**campaign_data).save()
        return campaign

class ThreatActor(StructuredNode):
    uuid=UniqueIdProperty()
    type = StringProperty(default='threat_actor')
    name = StringProperty(required=True)
    description = StringProperty()
    aliases = StringProperty()
    threat_actor_types = StringProperty()
    first_seen = DateTimeProperty()
    last_seen = DateTimeProperty()
    roles = StringProperty()
    goals = StringProperty()
    sophistication = StringProperty()
    resource_level = StringProperty()
    primary_motivation = StringProperty()
    secondary_motivations = StringProperty()
    personal_motive = StringProperty()

class AttackPattern(StructuredNode):
    uuid = UniqueIdProperty()
    type = StringProperty(default='attack-pattern')
    external_references = ArrayProperty(of_type='ExternalReference')
    name = StringProperty(required=True)
    description = StringProperty()
    aliases = ArrayProperty(of_type='string')
    kill_chain_phases = ArrayProperty(of_type='KillChainPhase')

    @staticmethod
    def create_attack_pattern(data):
        attack_pattern = AttackPattern(**data).save()
        return attack_pattern

class CourseOfAction(StructuredNode):
    CourseOfAction_uuid = UniqueIdProperty()
    type = StringProperty(default='course-of-action',)
    name = StringProperty(required=True)
    description = StringProperty()
    action = StringProperty()  # Reserved property

    @staticmethod
    def create_course_of_action(data):
        course_of_action = CourseOfAction(**data).save()
        return course_of_action

class Grouping(StructuredNode):
    Grouping_uuid = UniqueIdProperty()
    type = StringProperty(default='grouping')
    name = StringProperty()
    description = StringProperty()
    context = StringProperty(required=True)  # Should come from grouping-context-ov open vocabulary
    object_refs = ArrayProperty(of_type='string', required=True)  # List of object references

    @staticmethod
    def create_grouping(data):
        grouping = Grouping(**data).save()
        return grouping

class Identity(StructuredNode):
    Identity_uuid = UniqueIdProperty()
    type = StringProperty(default='identity')
    name = StringProperty(required=True)
    description = StringProperty()
    roles = ArrayProperty(of_type='string')
    identity_class = StringProperty()  # Should come from identity-class-ov open vocabulary
    sectors = ArrayProperty(of_type='string')  # Should come from industry-sector-ov open vocabulary
    contact_information = StringProperty()  # Can be more detailed based on actual requirements

    @staticmethod
    def create_identity(data):
        identity = Identity(**data).save()
        return identity

class Indicator(StructuredNode):
    Indicator_uuid = UniqueIdProperty()  # Unique identifier for each Indicator node
    type = StringProperty(default='indicator')
    name = StringProperty()
    description = StringProperty()
    indicator_types = ArrayProperty(of_type='string')  # List of indicator types from open vocabulary
    pattern = StringProperty(required=True)  # Detection pattern for this Indicator
    pattern_type = StringProperty(required=True)  # Pattern language used
    pattern_version = StringProperty()  # Version of the pattern language
    valid_from = DateTimeProperty(required=True)  # Time from which this Indicator is valid
    valid_until = DateTimeProperty()  # Time until which this Indicator is valid
    kill_chain_phases = ArrayProperty(of_type='string')  # List of Kill Chain Phases

    @staticmethod
    def create_indicator(data):
        indicator = Indicator(**data).save()
        return indicator

class Infrastructure(StructuredNode):
    Infrastructure_uuid = UniqueIdProperty()  # Unique identifier for each Infrastructure node
    type = StringProperty(default='infrastructure')
    name = StringProperty(required=True)
    description = StringProperty()
    infrastructure_types = ArrayProperty(of_type='string')  # List of infrastructure types from open vocabulary
    aliases = ArrayProperty(of_type='string')  # Alternative names
    kill_chain_phases = ArrayProperty(of_type='string')  # List of Kill Chain Phases
    first_seen = DateTimeProperty()  # Time when this Infrastructure was first seen
    last_seen = DateTimeProperty()  # Time when this Infrastructure was last seen

    @staticmethod
    def create_infrastructure(data):
        infrastructure = Infrastructure(**data).save()
        return infrastructure

class IntrusionSet(StructuredNode):
    IntrusionSet_uuid = UniqueIdProperty()  # Unique identifier for each Intrusion Set node
    type = StringProperty(default='intrusion-set')
    name = StringProperty(required=True)
    description = StringProperty()
    aliases = ArrayProperty(of_type='string')  # Alternative names used to identify this Intrusion Set
    first_seen = DateTimeProperty()  # Time when this Intrusion Set was first seen
    last_seen = DateTimeProperty()  # Time when this Intrusion Set was last seen
    goals = ArrayProperty(of_type='string')  # High-level goals of this Intrusion Set
    resource_level = StringProperty()  # Organizational level at which this Intrusion Set operates
    primary_motivation = StringProperty()  # Primary reason or motivation behind this Intrusion Set
    secondary_motivations = ArrayProperty(of_type='string')  # Secondary motivations

    @staticmethod
    def create_intrusion_set(data):
        intrusion_set = IntrusionSet(**data).save()
        return intrusion_set

class Location(StructuredNode):
    Location_uuid = UniqueIdProperty()  # Unique identifier for each Location node
    type = StringProperty(default='location' )
    name = StringProperty()
    description = StringProperty()
    latitude = FloatProperty()
    longitude = FloatProperty()
    precision = FloatProperty()
    region = StringProperty()  # Ideally, this should come from the region-ov open vocabulary
    country = StringProperty()  # ISO 3166-1 ALPHA-2 Code
    administrative_area = StringProperty()  # ISO 3166-2 Code
    city = StringProperty()
    street_address = StringProperty()
    postal_code = StringProperty()

    @staticmethod
    def create_location(data):
        location = Location(**data).save()
        return location

class MalwareAnalysis(StructuredNode):
    MalwareAnalysis_uuid = UniqueIdProperty()  # Unique identifier for each MalwareAnalysis node
    type = StringProperty(default='malware-analysis')
    product = StringProperty(required=True)
    version = StringProperty()
    host_vm_ref = StringProperty()  # Ideally, this should be an identifier for a SCO software object
    operating_system_ref = StringProperty()  # Ideally, this should be an identifier for a SCO software object
    installed_software_refs = ArrayProperty(StringProperty())  # List of identifiers for SCO software objects
    configuration_version = StringProperty()
    modules = ArrayProperty(StringProperty())
    analysis_engine_version = StringProperty()
    analysis_definition_version = StringProperty()
    submitted = DateTimeProperty()
    analysis_started = DateTimeProperty()
    analysis_ended = DateTimeProperty()
    result_name = StringProperty()
    result = StringProperty()  # Ideally, this should come from the malware-result-ov open vocabulary
    analysis_sco_refs = ArrayProperty(StringProperty())  # List of identifiers for SCOs
    sample_ref = StringProperty()  # Identifier for a malware sample

    @staticmethod
    def create_malware_analysis(data):
        malware_analysis = MalwareAnalysis(**data).save()
        return malware_analysis

class Malware(StructuredNode):
    Malware_uuid = UniqueIdProperty()  # Unique identifier for each Malware node
    type = StringProperty(default='malware')
    name = StringProperty(required=True)
    description = StringProperty()
    aliases = ArrayProperty(of_type='string')  # Alternative names used to identify this Malware
    malware_types = ArrayProperty(of_type='string')  # List of malware types from open vocabulary
    first_seen = DateTimeProperty()
    last_seen = DateTimeProperty()
    observed = DateTimeProperty()  # Time when this Malware was observed
    analysis = RelationshipTo('MalwareAnalysis', 'ANALYSED_BY')  # Relationship to Malware Analysis

    @staticmethod
    def create_malware(data):
        malware = Malware(**data).save()
        return malware



