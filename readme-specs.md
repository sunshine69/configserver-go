### 1. Functional Parity with Spring Cloud Config          
*   **Enhanced Profile Support:** The current implementation handles basic profile names bu
t could be improved to handle *multiple profiles* (e.g., `app=myapp&profile=dev,common`). I
n the Java version, it searches for all matching combinations and merges them. 
    *   **Fix/Propose:** Modify `serveValues` to iterate through comma-separated profile na
mes and merge property sources in a specific priority order.
*   **Search by Label (Git Backend):** While you have placeholders for Git configuration, t
he current logic doesn't fully implement the "Label" as a way to browse different branches/
tags if using a real Git backend.       
    *   **Fix/Propose:** Ensure that when `label` is provided, it is passed through to the 
git-based resolver to fetch specific commits or branches.

