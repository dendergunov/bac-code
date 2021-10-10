import spec
import argparse
import os


def main():
    parser = argparse.ArgumentParser(description='''OpenAPI specification analyzer and processor that annotates the 
    specification with BOLA properties''')
    parser.add_argument('spec_file', help='''Path to OpenAPI 3.0 specification file''')
    parser.add_argument('-d', '--dest', dest='savepath', help='''Processed YAML file destination,
    bola.yaml if not provided''')
    args = parser.parse_args()
    filepath = os.path.join(os.getcwd(), args.spec_file)
    if os.path.isfile(filepath) is not True:
        raise FileNotFoundError("Specified input file does not exist")
    analyzer = spec.OpenAPISpecAnalyzer()
    analyzer.parse_spec(filepath)

    if args.savepath is None:
        args.savepath = 'bola.yaml'
    analyzer.save_spec(args.savepath)

if __name__ == "__main__":
    main()
