import pandas as pd 




def entity_type_from_id(e:str) -> str: 
    ''' Extracts the entity type from the given entity ID. Entity types are: attack-pattern, campaign, 
    course-of-action, intrusion-set, malware, tool, tactic. 
    
        Args: 
            e (str): an entity ID (campaign, tactic, tool, etc)
        
        Returns:
            str: the entity type as a string
    '''
    return e.split('--')[0]
            

def get_relationship_entity_types(relationship_dict:dict) -> tuple[str, str]:
    ''' Gets the types of entities from the given relationship. Entity types are: attack-pattern, campaign, 
    course-of-action, intrusion-set, malware, tool, tactic.
    
        Args: 
            relationship_dict (dict): a relationship in dictionary format
            
        Returns: 
            tuple[str, str]: returns a tuple containing two values that dictate the two types of entities in the 
            given relationship.
    '''
    
    # Extract the IDs for the two entities in the relationship, i.e. the source and target 
    return (
        entity_type_from_id(relationship_dict['source_ref']),
        entity_type_from_id(relationship_dict['target_ref'])
    )
    
    
def tool_name_from_id(tools:list[dict], tool_id:str) -> str: 
    tool_name:str = None
    
    for t in tools: 
        if t['id'] == tool_id: 
            tool_name = t['name'] 
            break
    
    return tool_name