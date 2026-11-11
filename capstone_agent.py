import os
from crewai import Agent, Crew, LLM, Process, Task

# 1. Point CrewAI to your local Ollama instance
# Note: You have 'llama3.2' installed locally in Ollama. 
# If you want qwen2.5-coder:7b, run `ollama pull qwen2.5-coder:7b` first.
local_llm = LLM(
    model="ollama/llama3.2",
    base_url="http://localhost:11434",
)

# 2. Define Agent 1: The Technical Architect / Planner
planner = Agent(
    role="Software Architect",
    goal="Design a clean, modular technical plan for the requested feature or capstone component.",
    backstory="You are an expert senior software engineer who breaks down requirements into step-by-step logic, file structures, and function signatures before any code is written.",
    verbose=True,
    llm=local_llm,
    allow_delegation=False,
)

# 3. Define Agent 2: The Master Coder
coder = Agent(
    role="Senior Developer",
    goal="Write production-ready, clean, well-commented code based strictly on the Architect's plan.",
    backstory="You write robust Python/Go code, handle edge cases cleanly, and output clean code blocks ready for integration.",
    verbose=True,
    llm=local_llm,
    allow_delegation=False,
)

# 4. Define the Task for your Capstone Project
# (Change this prompt to whatever feature you are building next for your project!)
project_prompt = """
Build a Python utility module that connects to a local SQLite database, 
fetches user logs, filters them by date range, and exports them to a structured JSON file.
"""

plan_task = Task(
    description=f"Analyze the following requirement and create a clear coding blueprint: {project_prompt}",
    expected_output="A step-by-step architecture plan with function names and logic flow.",
    agent=planner,
)

code_task = Task(
    description="Using the architecture plan provided by the planner, write the complete, clean Python code implementation.",
    expected_output="Clean, executable Python code blocks with comments.",
    agent=coder,
)

# 5. Assemble the Crew (Sequential execution to save your laptop's RAM)
capstone_crew = Crew(
    agents=[planner, coder],
    tasks=[plan_task, code_task],
    process=Process.sequential,  # Runs one after the other so your 16GB RAM handles it easily
    verbose=True,
)

if __name__ == "__main__":
    print("## Starting Local Multi-Agent Pipeline for Capstone Project ##")
    result = capstone_crew.kickoff()
    print("\n\n########################")
    print("## RESULT CODE & PLAN ##")
    print("########################\n")
    print(result)