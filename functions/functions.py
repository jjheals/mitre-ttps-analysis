import pandas as pd 
import json
from tabulate import tabulate 
import numpy as np 


def filter_dict(lod:list[dict], k:str, v:str) -> list[dict]: 
    ''' Filters a given list of dictionaries for the given value [v] at the given key [k]. 
    
        Args: 
            lod (list[dict]): a list of dictionaries to search.
            k (str): the key to filter by.
            v (str): the value to filter for.
            
        Returns: 
            list[dict]: a list of dicts filtered by the given parameters. 
    '''
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
    ''' Takes in a list of dictionaries and cleans it appropriately, including extracting 
    the sources.
    
        Args: 
            lod (list[dict]): list of dictionaries to parse.
            
        Returns: 
            dict[str, list[dict]]: a dictionary with two keys: "dicts", which is the cleaned
            list of dictionaries, and "sources", which is a list of dicts with the sources
            for each entry. 
    '''
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
    
    
def create_csvs(lod:list[dict], sources:list[dict], filepath1:str, sources_filepath:str, print_debug:bool=False) -> None:
    ''' Create two CSVs, one for all the "dictionaries" (entities/items) and one for the sources. 
    
        Args: 
            lod (list[dict]): a list of all entities as dictionaries (for CSV1).
            sources (list[dict]): a list of all the sources as dictionaries (for CSV2). 
            filepath1 (str): filepath to save CSV1.
            sources_filepath (str): filepath to save CSV2.
            print_debug (bool, optional): specify to print debug statements or not. Defaults to False. 
    
        Returns: 
            None: creates the CSVs at filepath1 and sources_filepath
    '''
    # Convert the list of dicts (lod) to a df
    df1:pd.DataFrame = pd.DataFrame(lod)
    
    # Drop unnecessary columns 
    drop_cols:list[str] = [
        'external_references',        # Not needed
        'x_mitre_deprecated',         # Not relevant 
        'x_mitre_version',            # Not relevant 
        'x_mitre_modified_by_ref',    # Not relevant
        'spec_version',               # Not relevant
        'x_mitre_contributors',       # Not relevant
        'created_by_ref',             # Not relevant 
        'revoked',                    # Not relevant 
        'modified',                   # Not relevant 
        'created',                    # Not relevant 
        'object_marking_refs',        # Not relevant 
        'x_mitre_attack_spec_version' # Not relevant
    ]
    
    df1.drop([c for c in drop_cols if c in df1.columns], axis=1, inplace=True)
    
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
    ''' Extracts the name of the entity from [lod] that has the given ID. NOTE: assumes [id] is a
    unique identifier in [lod] with the key 'id'.
    
        Args: 
            lod (list[dict]): list of dicts to search for the ID.
            id (str): id to search for. 
        
        Returns: 
            str: the name of the entity as a string.        
    '''
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
    ''' Get all the relationships containing the target_str in one of the entities. 
    
        Args: 
            relationships (list[dict]): a list of relationships (as dicts) to search through.
            target_str (str): the target string to search for. E.g. "malware", "tool", "intrusion-set", etc. 
            
        Returns: 
            list[dict]: a list of the matching relationships as dicts.         
    '''
    return_relationships:list[dict] = []
    
    for r in relationships: 
        these_entity_types:tuple = get_relationship_entity_types(r) 
        
        if target_str in these_entity_types: return_relationships.append(r)
        
    return return_relationships


def get_entities_for_actor(entities_of_type:list[dict], target_entity_type:str, actor:dict, entity_name:str, print_debug:bool=False) -> list[dict]:
    ''' Retrieves the entities (dicts) from [entities_of_type] that match the [target_entity_type]. 
    NOTE: Assumes the actor's relationships exist in "data/jsons/[actor_name]/relationships.json 
   
        Args: 
            entities_of_type (list[dict]): a list of the entities to search as dictionaries (e.g. campaigns, tools, etc.)
            target_entity_type (str): the type of entity in entities_of_type. Needed to identify the ID properly. 
            actor (dict): the actor as a dictionary (i.e. an "intrusion-set").
            entity_name (str): a pretty string for the name of the entity that appears in the resulting dictionaries. 
            print_debug (bool, optional): specify whether to print debug statements. Defaults to False.

        Returns: 
            list[dict]: a list of dictionaries that can be dumped to a JSON for this actor or analyzed separately.
    '''
    # DEBUG prints
    if(print_debug):
        print(f'\nSearching for {target_entity_type} for actor name {actor["name"]} ({actor["id"]}) ')
    
    # Load all the relationships with for this actor from persistent storage
    with open(f'data/jsons/{actor["name"].replace(" ", "-")}/relationships.json') as file: 
        all_actor_relationships:list[dict] = json.load(file)
    
    # DEBUG prints
    if(print_debug):
        print(f"\tFound {len(all_actor_relationships)} relationships for this actor.")
    
    # From all the actor's relationships, extract those with tools
    rels_with_entity_type:list[dict] = relationships_with_x(all_actor_relationships, target_entity_type)
    
    # DEBUG prints
    if(print_debug):
        print(f'\tFound {len(rels_with_entity_type)} relationships for {actor["name"]} containing "{target_entity_type}".')
    
    # Extract the entity matches for each relationship
    actor_entity_matches:list[dict] = []
    
    for r in rels_with_entity_type: 
        this_entity_id:str = r['target_ref'] if target_entity_type in r['target_ref'] else r['source_ref']
        
        for e in entities_of_type: 
            if e['id'] == this_entity_id: 
                
                if(print_debug): 
                    print(f'\tMatched "{this_entity_id}" with "{e["name"]}".')
                    print(f'\tThis entity (e) KEYS:')
                    for k in e.keys(): print(f'\t\t{k}')
                
                actor_entity_matches.append({
                    f'{entity_name} Name': name_from_id(entities_of_type, this_entity_id),
                    f'id': this_entity_id,
                    'Description': e['description'],
                    'Relationship ID': r['id'],
                    'Relationship Type': r['relationship_type']
                    }
                )
                break
    
    # DEBUG prints
    if(print_debug): 
        print(
            tabulate(
                actor_entity_matches, 
                headers={ k : k for k in actor_entity_matches[0].keys() } if actor_entity_matches else {}
            )
        )

    return actor_entity_matches
    

def generate_similarity_table(similarity_matrix:np.matrix, row_labels:list, table_headers:list[str]=['Label 1', 'Label 2', 'Similarity Rating'], check_if_aliases:bool=False) -> tuple[list[list], str]:
    ''' Generates a similarity table from the given similarity matrix 
    
        Args: 
            similarity_matrix (np.matrix): the similarity matrix 
            row_labels (list): list containing the labels for the rows (in order as they appear in the matrix) 
            table_headers (list[str], optional): list of strings to use as the headers for the table. Defaults to generic labels and assumes three columns.
            check_if_aliases (bool, optional): boolean whether to compare label 1 and label 2 to see if they are aliases. Only applies to threat actor names. Defaults to false.
            
        Returns: 
            tuple[list[list], str]: the table as a list of lists and a prettified string of the table created using tabulate. 
    
    '''
    
    # If we're checking actor aliases, then load the aliases json
    if check_if_aliases: 
        with open('data/jsons/actor-aliases.json', 'r') as file:
            aliases:dict[str, list[str]] = json.load(file)
    
    # most_similar := list of the most similar entries as indexes to each entry
    most_similar:list[int] = []
    
    for i in range(similarity_matrix.shape[0]):
        similarity_matrix[i, i] = -1                                 # Exclude the self-similarity by setting it to a very low value
        most_similar_row_index = np.argmax(similarity_matrix[i])     # Find the index of the most similar row
        most_similar.append(most_similar_row_index)
        
    # Construct the table for most similar rows 
    table_results:list[tuple] = []
    for i, row in enumerate(most_similar):
        
        # Convert the row and cols to their labels
        label1 = row_labels[i]
        label2 = row_labels[row] 
        rating:float = round(similarity_matrix[i][row], 2)
        
        # Check if the rating is 0, i.e. there are no similarities with any other entity
        if rating == 0: label2 = 'None'
        
        # Construct the row of the table
        this_row:list = [label1, label2, rating]
        
        # Check aliases if configured
        if check_if_aliases: 
            try: is_alias:bool = bool((label1 in aliases[label2]) or (label2 in aliases[label1]))
            except KeyError: is_alias:bool = False
            this_row.append(is_alias)
        
        # Append this row to the table 
        table_results.append(this_row)

    # Sort the table results by the first entry and tabulate the results into a table string
    alphabetical_table_results:list[tuple] = sorted(table_results, key=lambda x: x[0])
    most_similar_table_pretty = tabulate(alphabetical_table_results, headers=table_headers)
    
    # Return the alphabetized table and the pretty string of the table
    return alphabetical_table_results, most_similar_table_pretty