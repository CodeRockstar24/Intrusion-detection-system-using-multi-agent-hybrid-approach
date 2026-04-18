from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task


#agent class definitions
@CrewBase
class MyCrew:
    """MyCrew"""
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    @agent
    def research_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['research_agent'],
            allow_delegation=False,
            verbose=True,
      
        )
    
    @agent
    def response_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['response_agent'],
            allow_delegation=False,
            verbose=True,
        
        )
    
    
    @task
    def research_attack_task(self) -> Task:
        return Task(
            config=self.tasks_config['research_attack_task'],
            agent=self.research_agent()
        )

    @task
    def response_action_task(self) -> Task:
        return Task(
            config=self.tasks_config['response_action_task'],
            agent=self.response_agent(),
        )


    @crew
    def crew(self) -> Crew:
        return Crew(
            agents=self.agents,  # Automatically created by the @agent decorator
            tasks=self.tasks,  # Automatically created by the @task decorator
            process=Process.sequential,
            verbose=True, 
        )