# SmartTracker

SmartTracker is a Python-based application designed to analyze memory dumps and efficiently monitor system performance. It leverages powerful libraries to provide insightful diagnostics and logging capabilities, making it an essential tool for developers and system administrators.

## Features

- **Memory Analysis:** Analyze memory dumps to identify potential issues and optimize performance.
- **System Monitoring:** Utilize `psutil` to monitor system resources and performance metrics.
- **Logging:** Comprehensive logging for tracking application behavior and troubleshooting.
- **Cheat Engine-like Functionality:** Inject Python scripts into target processes for dynamic memory manipulation.

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
python main.py
```

SmartTracker/  
├── dump/  
│ ├── analyzer/  
│ │ ├── memory_analyzer.py  
│ ├── base/  
│ │ ├── memory_dumper.py  
│ ├── memory/  
│ │ ├── memory_entry.py  
│ ├── utils/  
│ │ ├── pointers.py  
│ ├── logging/  
│ │ ├── logging_config.py  
│ └── __init__.py  
├── gui/  
│ ├── analyze_process/  
│ │ ├── controllers/  
│ │ │ ├── search_controller.py  
│ │ ├── analysis_tab.py  
│ │ ├── main_window.py  
│ ├── process_selector/  
│ │ ├── controllers/  
│ │ │ ├── process_controller.py  
│ │ │ ├── module_controller.py  
│ │ ├── main_frame.py  
│ └── __init__.py  
├── .gitignore  
├── requirements.txt  
└── README.md  

- **drop/**: Contains modules related to memory analysis.
  - **analyzer/**:
    - **memory_analyzer.py**: Handles memory analysis tasks.
  - **base/**:
    - **memory_dumper.py**: Responsible for dumping memory from processes.
  - **memory/**:
    - **memory_entry.py**: Dataclass representing a memory entry.
  - **utils/**:
    - **pointers.py**: Utilities for pointer operations.
  - **logging/**:
    - **logging_config.py**: Configures logging settings.
  - **__init__.py**: Initializes the dump package.
- **gui/**: Contains graphical user interface components.
  - **analyze_process/**:
    - **controllers/**:
      - **search_controller.py**: Handles search functionalities.
    - **analysis_tab.py**: GUI tab for displaying analysis results.
    - **main_window.py**: Main analysis window.
  - **process_selector/**:
    - **controllers/**:
      - **process_controller.py**: Manages process dumping.
      - **module_controller.py**: Manages module listings.
    - **main_frame.py**: Main frame for the process selector.
  - **__init__.py**: Initializes the GUI package.
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