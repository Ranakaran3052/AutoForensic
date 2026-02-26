def generate_timeline(metadata_dict):
    timeline = []

    for key, value in metadata_dict.items():
        timeline.append((value, key))

    timeline.sort()

    return timeline