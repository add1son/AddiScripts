import os

# PURPOSE: Merges multiple Markdown files from a folder into a single document 
# for easier organization, archiving, or LLM ingestion.

# CONFIGURATION
# Set to r"." to run directly inside your notes folder, or use an absolute path
source_folder = r"."
output_filename = "combined_notes.md"


def combine_markdown_files():
    output_path = os.path.join(source_folder, output_filename)
    
    try:
        all_files = os.listdir(source_folder)
    except FileNotFoundError:
        print(f"Error: The folder '{source_folder}' was not found.")
        return

    # Grab only markdown files and skip the output file if it already exists
    md_files = [f for f in all_files if f.endswith('.md') and f != output_filename]
    md_files.sort()

    if not md_files:
        print("No markdown files found to combine.")
        return

    print(f"Found {len(md_files)} markdown files. Combining...")

    try:
        with open(output_path, 'w', encoding='utf-8') as outfile:
            # Initialize master document header
            outfile.write("# Generation loop initialized \n\n---\n\n")

            for filename in md_files:
                file_path = os.path.join(source_folder, filename)
                date_header = os.path.splitext(filename)[0]

                try:
                    with open(file_path, 'r', encoding='utf-8') as infile:
                        content = infile.read()
                        
                        # Append content with the filename/date as the header
                        outfile.write(f"## {date_header}\n\n")
                        outfile.write(content)
                        outfile.write("\n\n---\n\n")
                        
                except Exception as e:
                    print(f"Error reading {filename}: {e}")

        print(f"Success! Combined file created at: {output_path}")
        
    except Exception as e:
        print(f"Error writing to output file: {e}")


if __name__ == "__main__":
    combine_markdown_files()