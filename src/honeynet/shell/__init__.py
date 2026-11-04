"""Fake shell + fake filesystem shared by the SSH and Telnet honeypots.

Nothing here ever executes attacker input: commands are pure-Python emulations
that read/write an in-memory overlay filesystem.
"""
