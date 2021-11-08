import argparse
import os

import annotator
import attack_analyzer

import time

def main():
    parser = argparse.ArgumentParser(description='''OpenAPI specification analyzer and processor that annotates the 
    specification with BOLA properties''')
    parser.add_argument('spec_file', help='''Path to OpenAPI 3.0 specification file''')
    parser.add_argument('--pd', '--properties-dest', dest='properties_savepath', default='bola_properties.yml',
                        help='''Annotated YAML spec file destination, bola_properties.yml if not provided''')
    parser.add_argument('--ad', '--attack-dest', dest='attacks_savepath', default='bola_attacks.yml',
                        help='''Proposed attacks YAML spec file destination, bola_attacks.yml if not provided''')
    args = parser.parse_args()
    filepath = os.path.join(os.getcwd(), args.spec_file)
    if os.path.isfile(filepath) is not True:
        raise FileNotFoundError("Specified input file does not exist")

    start = time.time()
    property_analyzer = annotator.OpenAPISpecAnnotator()
    property_analyzer.parse_spec(filepath)
    property_analyzer.save_spec(args.properties_savepath)

    attack_analyzer_instance = attack_analyzer.AttackAnalyzer()
    attack_analyzer_instance.estimate_attacks(args.properties_savepath)
    attack_analyzer_instance.save_output(args.attacks_savepath)
    end = time.time()
    print("Done in", end-start, "seconds")

if __name__ == "__main__":
    main()
