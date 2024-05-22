import pandas as pd 


def filter_dict(lod:list[dict], k:str, v:str) -> list[dict]: 
    return [
        d for d in lod if d[k] == v
    ] 
    

def extract_external_references(d:dict) -> dict: 
    ''' Extracts the "external_references" values from the given dictionary and returns a dict containing the 
    key : val pairs.
    
        Args: 
            d (dict): a dictionary in the format of the MITRE tools, campaigns, etc. 
            
        Returns: 
            (dict): a dictionary with the sources extracted from "external_references" 
    '''
    # Extract the external_references
    try: external_references:list[dict] = d['external_references']
    
    # If the "external_references" key doesn't exist, then we can return an empty dict since there is 
    # nothing to extract
    except KeyError: return {}
    except TypeError: return {}
    
    # Iterate over the external references (sources) and extract the source information for each
    if external_references: 
        for s in external_references: 
        
            # Create a dict for this source
            this_source_dict:dict = {
                'id': d['id'],
                'source_name': s['source_name']
            }
            
            # Extract URL if available
            try: this_source_dict['url'] = s['url']
            except KeyError: this_source_dict['url'] = None 
            
            # Extract description if available
            try: this_source_dict['description'] = s['description']
            except KeyError: this_source_dict['description'] = None
            
            # Extract an external ID if available
            try: this_source_dict['external_id'] = s['external_id'] 
            except KeyError: this_source_dict['external_id'] = None
        
        return this_source_dict
    else:
        return {
            'id': None,
            'source_name': None,
            'url': None,
            'description': None,
            'external_id': None
        }
        
        
def handle_list_of_dict(lod:list[dict]) -> dict[str, list[dict]]:
    
    # Get all the keys for all the dictionaries 
    all_dict_keys:list[list[str]] = [ list(d.keys()) for d in lod ]

    # Sort this list in ascending order by length (i.e. by number of keys)
    all_sorted_keys:list[list[str]] = sorted(all_dict_keys, key=len)

    # Take the last list of keys for the "fill keys" since that has the most keys
    fill_keys:list[str] = all_sorted_keys[len(all_sorted_keys) - 1]

    # Dict for the 'external_references' column (sources)
    sources:list[dict] = []

    # Iterate over all the dictionaries
    for d in lod: 
        
        # For this dict, iterate over the fill keys and add any missing keys with None values
        for k in fill_keys: 
            if k not in d: d[k] = None
        
        # Since the object_marking_refs column is given as a list with only one str, extract that to be a column of strs instead
        try: d['object_marking_refs'] = d['object_marking_refs'][0]
        except TypeError: d['object_marking_refs'] = None
        
        # Extract the external_references 
        this_source_dict:dict = extract_external_references(d)
        
        # Append this_source_dict to the intrusion_set_sources list
        sources.append(this_source_dict) 
    
    return {
        'dicts': lod, 
        'sources': sources
    }
    
    
def create_csvs(lod:list[dict], sources:list[dict], filepath1:str, sources_filepath:str, print_debug:bool=False):
    
    # Convert the list of dicts (lod) to a df
    df1:pd.DataFrame = pd.DataFrame(lod)
    df1.drop('external_references', axis=1, inplace=True)

    # Convert the sources list (sources) to a df
    sources_df:pd.DataFrame = pd.DataFrame(sources)

    # Dump the DFs to CSVs
    df1.to_csv(filepath1, index=False)
    sources_df.to_csv(sources_filepath, index=False)

    # Print details
    if print_debug: 
        print(f'Saved {len(df1)} objects to "{filepath1}".') 
        print(f'Saved {len(sources)} sources to "{sources_filepath}".')
        

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
    
    
def name_from_id(lod:list[dict], id:str) -> str: 
    name_:str = None
    
    for d in lod: 
        if d['id'] == id: 
            name_ = d['name'] 
            break
    
    return name_


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


def relationships_with_x(relationships:list[dict], target_str:str) -> list[dict]: 
    
    return_relationships:list[dict] = []
    
    for r in relationships: 
        these_entity_types:tuple = get_relationship_entity_types(r) 
        
        if target_str in these_entity_types: return_relationships.append(r)
        
    return return_relationships

