# SmartTracker

SmartTracker is a Python-based application designed to analyze memory dumps, manage databases, and efficiently monitor system performance. It leverages powerful libraries to provide insightful diagnostics and logging capabilities, making it an essential tool for developers and system administrators.

## Features

- **Memory Analysis:** Analyze memory dumps to identify potential issues and optimize performance.
- **Database Management:** Efficiently handle and interact with databases for seamless data storage and retrieval.
- **System Monitoring:** Utilize `psutil` to monitor system resources and performance metrics.
- **Logging:** Comprehensive logging for tracking application behavior and troubleshooting.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/needitem/SmartTracker.git
   ```

2. **Navigate to the Project Directory**

   ```bash
   cd SmartTracker
   ```

3. **Create a Virtual Environment (Optional but Recommended)**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To execute the memory dump analyzer, run the following command:

```bash
python gui/main.py
```

SmartTracker/
├── dump/
│ ├── dump_analyzer.py
│ ├── memory_analyzer.py
│ ├── memory_dumper.py
│ ├── database.py
│ ├── memory_entry.py
│ ├── utils.py
│ └── init.py
├── gui/
│ ├── analyze_process.py
│ └── process_selector.py
├── .gitignore
├── requirements.txt
└── README.md

- **dump/**: Contains modules related to memory analysis and database interactions.
  - **dump_analyzer.py**: Main script for analyzing memory dumps.
  - **memory_analyzer.py**: Module for handling memory analysis tasks.
  - **memory_dumper.py**: Module responsible for dumping memory from processes.
  - **database.py**: Module for managing database operations.
  - **memory_entry.py**: Dataclass representing a memory entry.
  - **utils.py**: Utility functions for process-related operations.
  - ****init**.py**: Initializes the dump package.
- **gui/**: Contains graphical user interface components.
  - **analyze_process.py**: GUI window for analyzing processes.
  - **process_selector.py**: GUI component for selecting processes to analyze.
- **.gitignore**: Specifies files and directories to be ignored by Git.
- **requirements.txt**: Lists Python dependencies required for the project.
- **README.md**: Documentation and instructions for the project.

**Description:**  
The `ProcessSelector` class provides a GUI component for selecting and dumping memory from running processes. It includes functionality to refresh the list of active processes, handle user selections, and initiate memory dumps in separate threads to keep the GUI responsive. Comprehensive logging ensures that all actions and potential errors are appropriately recorded.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your enhancements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or support, please reach out to [th07290828@gmail.com](mailto:th07290828@gmail.com).
