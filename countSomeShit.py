import sys
import string

def normalize(word):
    return word.strip(string.punctuation).lower()

def top_n_words(filename, n):
    counts = {}
    with open(filename, encoding='utf-8') as f:
        for line in f:
            for raw in line.split():
                w = normalize(raw)
                if not w: 
                    continue
                counts[w] = counts.get(w, 0) + 1

    sorted_words = sorted(
        counts.items(),
        key=lambda item: (-item[1], item[0])
    )
    return sorted_words[:n]

def main():

    filename, n_str = sys.argv[1], sys.argv[2]
    try:
        n = int(n_str)
    except ValueError:
        print("Error: N must be an integer")
        sys.exit(1)

    for rank, (word, cnt) in enumerate(top_n_words(filename, n), start=1):
        print(f"{rank} – word \"{word}\" {cnt} times")

if __name__ == "__main__":
    main()