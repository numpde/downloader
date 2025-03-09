from p_tqdm import p_map

def compute(x):
    # Simulate a task
    return x * x

if __name__ == "__main__":
    results = p_map(compute, range(10))
