import os
import re

def count_words_in_markdown_files(root_dir):
    """
    Searches for .md files in child directories and counts the total words.

    Args:
        root_dir (str): The root directory to start the search from.

    Returns:
        int: The total number of words found in all .md files.
    """

    total_word_count = 0

    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith(".md"):
                filepath = os.path.join(dirpath, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as file:
                        content = file.read()
                        words = re.findall(r'\b\w+\b', content.lower())
                        total_word_count += len(words)
                except FileNotFoundError:
                    print(f"Error: File not found: {filepath}")
                except PermissionError:
                    print(f"Error: Permission denied: {filepath}")
                except UnicodeDecodeError:
                    print(f"Error: Could not decode file {filepath}. Ensure it is UTF-8 encoded.")
                except Exception as e:
                    print(f"An unexpected error occurred processing {filepath}: {e}")

    return total_word_count

if __name__ == "__main__":
    root_directory = r"$path"  # Hardcoded directory
    word_count = count_words_in_markdown_files(root_directory)
    print(f"Total word count in .md files: {word_count}")