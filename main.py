import os

from tqdm import tqdm
import process_binary
import similarity_matching
import visualize
import LCS_similarity
import MBA_similarity
import pandas as pd

def binary_similarity_to_dataframe(confusion_matrix,location1,location2):
    # Initialize lists to store data for DataFrame
    binary1_functions = []
    binary2_functions = []
    similarity_scores = []

    # Iterate through the confusion matrix to populate the lists
    for binary1_function, binary2_data in confusion_matrix.items():
        for binary2_function, similarity_score in binary2_data.items():
            binary1_functions.append(binary1_function)
            binary2_functions.append(binary2_function)
            similarity_scores.append(similarity_score)
    #print(location1.split("/")[2:])
    #print(location2.split("/")[2:])
    location1 = '_'.join(location1.split("/")[2:])
    location2 = '_'.join(location2.split("/")[2:])
    #print()
    #print(location1)
    #print(location2)
    if location1 == location2:
        location1 += "_1"
        location2 += "_2"

    # Create DataFrame
    df = pd.DataFrame({
        location1: binary1_functions,
        location2: binary2_functions,
        'Similarity Score': similarity_scores
    })

    return df

def testing(location1, location2):
    bin1 = process_binary.Binary(location1)
    b1 = bin1.get_function_paths()
    bin2 = process_binary.Binary(location2)
    b2 = bin2.get_function_paths()
    # print(b1==b1)
    # print(b2==b2)
    # print(b1==b2)
    # exit()
    matcher_norm = similarity_matching.Similarity(b1, b2, "test/others/smol")
    confusion_norm = matcher_norm.binary_similarity()
    
    return binary_similarity_to_dataframe(confusion_norm, location1, location2)
    
    # v = visualize.Visualize(confusion_norm, location1, location2, 'Normal')
    # v.plot_confusion_matrix()

def safe_to_csv(df, filename):
    # Get the directory path from the filename
    #print(filename)
    directory = os.path.dirname(filename)

    # Create the directory if it doesn't exist
    if not os.path.exists(directory):
        os.makedirs(directory)

    # Write the DataFrame to CSV
    df.to_csv(filename, index=False) 


if __name__ == "__main__":
    compilers = ["gcc","clang"]
    optimizations = ["O1", "Og"]
    #bins = "cat  cp  cut  date  df  du  echo  ghost  head  ln  ls  mkdir  mv  pwd  rm  rmdir  sort  tail  uname  who".split()
    #bins = ["date", "ghost", "uname"]
    bins = ["cat", "cp", "cut"]
    

    for i in tqdm(range(len(bins))):
        for j in tqdm(range(i,len(bins))):
            bin1 = bins[i]
            bin2 = bins[j]
            for k in range(len(optimizations)):
                for l in range(k, len(optimizations)):
                    opt1 = optimizations[k]
                    opt2 = optimizations[l]
                    for m in range(len(compilers)):
                        for n in range(m, len(compilers)):
                            c1 = compilers[m]
                            c2 = compilers[n]
                            try:
                                result = testing(f"test/coreutils/{c1}/x86/{opt1}/{bin1}",f"test/coreutils/{c2}/x86/{opt2}/{bin2}")
                                safe_to_csv(result,f"output/{c1}_{c2}/{opt1}_{opt2}/{bin1}_{bin2}.csv")
                            except:
                                print(f"{c1} - {c2} / {opt1} - {opt2} / {bin1} - {bin2} failed")
                                pass
                            
                            #exit()
