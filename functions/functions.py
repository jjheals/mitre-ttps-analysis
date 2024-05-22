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


def get_all_relationships_for_actor(relationships:list[dict], actors:list[dict], actor_name:str, search_aliases:bool=True) -> list[dict]:
    ''' Gets all the relationships for the given actor_name. 
    
        Args: 
            relationships (list[dict]): a list of relationships to search as dictionaries
            actors (list[dict]): a list of actors to search as dictionaries
            actor_name (str): the name of the actor to search for
            search_aliases (bool, optional): specify whether to include aliases in the search (i.e. search aliases for actor_name). Defaults to True. 
            
        Returns: 
            list[dict]: a list of the matching relationships as dictionaries containing the specified actor as EITHER a 
            source or target of the relationship. 
    '''
    
    # actor_relationships := a list of relationships (as dicts) that contain this actor (i.e. the list to return)
    actor_relationships:list[dict] = []
    
    # Get the ID for this actor
    # actor_id := ID for the actor wit this name 
    actor_id:str = ''    
    
    # Iterate over the actors and find the one with this name
    for a in actors:
        if(
            # Clause 1: name matches
            (a['name'] == actor_name) or                        
            # Clause 2: search aliases is True and the given name is an alias
            (a['aliases'] and search_aliases and (actor_name in a['aliases']))     
        ): 
            actor_id = a['id']
            break 
            
    # Check to confirm we got a result, return none if not 
    if not actor_id: return []

    # Find all the relationships with this ID
    for r in relationships: 
        if r['target_ref'] == actor_id or r['source_ref'] == actor_id: 
             actor_relationships.append(r)
             
    return actor_relationships


def relationships_with_tools(relationships:list[dict]) -> list[dict]: 
    
    return_relationships:list[dict] = []
    
    for r in relationships: 
        these_entity_types:tuple = get_relationship_entity_types(r) 
        
        if 'tool' in these_entity_types: return_relationships.append(r)
        
    return return_relationships

