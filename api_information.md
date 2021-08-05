# Running list of CTF API information**

**CTFd**
```
/api/v1
/api/v1/challenges
/api/v1/teams/me
/api/v1/teams/me/solves
/api/v1/users/me --- if user-based CTF
/api/v2/users/me/solves --- if user-based CTF
/login --- *need nonce for login*

note: there might be a new version to this API?
```

</br>

**RACTF**
```
https://docs.ractf.co.uk/openapi-schema
/api/v2
/api/v2/challenges
/api/v2/challenges/categories
/api/v2/challenges/categories/{id}
/api/v2/challenges/files
/api/v2/challenges/files/{id}
/api/v2/challenges/scores
/api/v2/challenges/scores/{id}
/api/v2/challenges/submit_flag
/api/v2/challenges/{id}
/api/v2/leaderboard/graph
/api/v2/member
/api/v2/member/self
/api/v2/member/{id}
/api/v2/team
/api/v2/team/self
/api/v2/team/{id}
/auth/create_bot --- I wonder what this is for???
/auth/login
/challenges
```

</br>

**rCTF**
```
/api/v1
/api/v1/auth/login --- login done with team token
heads = {
        "Content-Type": "application/json",
        "Authorization": "Bearer null"
}
/api/v1/challs --- need to use Bearer token for authorization, referer needs to be "/challs"
/api/v1/users/me

this API probably won't get used unless they add users to the system
```

</br>

Possibly outdated CTF platforms:
- CTFx
- redCTF

</br>

CTF platforms with potential integration:
- ImaginaryCTF
- CTFZone
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
