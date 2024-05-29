# actor-data-analysis 

## Description

Performing data analysis on open source data regarding threat actor TTPs. This data came from [MITRE's open source STIX repository](https://github.com/mitre-attack/attack-stix-data/tree/master). 

## Data Structure & Format

### Intrusion Sets (Actors) 

Per MITRE's naming conventions, an "Intrusion set" is a Threat Actor (TA). The structure for a TA is based on MITRE's original STIX structure with the following added attributes: 

- "motivations": a list of motivations for previous attacks by this threat actor. Possible values are:
    - "Financial" 
    - "Espionage"
    - "Hacktivism"

The structure for a TA in JSON/dict format is as follows: 
```json 
    { 
        "modified": "last time this obj was modified", 
        "name": "TA Primary Name", 
        "description": "Description in MD format for this threat actor, most originally from MITRE.",
        "aliases": [ 
            "A list",
            "of aliases",
            "for each",
            "threat actor"
        ],
        "motivations": [
            "A list",
            "of motivations",
            "that this TA",
            "has had in at least one attack",
            "in the past"
        ],
        "x_mitre_deprecated": "type = bool => flag by MITRE",
        "x_mitre_version": "int/float => MITRE version",
        "type": "intrusion-set",
        "id": "intrusion-set--s0me-really-long-un1que-ID",
        "created": "date created by MITRE",
        "created_by_ref": "identity--s0me-really-long-un1que-ID",
        "revoked": "type = bool => flag by MITRE",
        "external_references": [
            {
                "source_name": "name-of-source-or-attribute-source-is-for",
                "description": "Why is this source relevant OR citation",
                "url": "http://url-to-source.com/not-in-all-objects/"
            },
            {
                "source_name": "Motivation",
                "description": "TA1 is motivated by Motivation in at least some of their operations",
                "url": "http://url-to-source.com/for/attack/motivated-by/Motivation"
            },
            {
                "source_name": "Actor Alias",
                "description": "(Citation: Crowdstrike or MS or Kapersky or something)"
            }
        ],
        "object_marking_refs": [
            "marking-definition--s0me-really-long-un1que-ID"
        ],
        "x_mitre_domains": [
            "MITRE-domains",
            "targeted-by-TA",
            "example-is",
            "enterprise-attack"
        ],
        "x_mitre_attack_spec_version": "MITRE.version.num",

    }
```