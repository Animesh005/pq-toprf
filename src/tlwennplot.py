import pandas as pd
import matplotlib.pyplot as plt


dfs = []
for i in [8, 16, 32, 64]:
    dfs.append(pd.read_csv(f"test/tlwenn/{i}.csv", names=["parties", str(i)]))

df = dfs[0]
for i in range(1, len(dfs)):
    df = df.merge(dfs[i], on="parties", how="inner")


df.plot.line(x="parties")

plt.ylabel("Max Error Bound")
plt.xlabel("Parties")
plt.show()