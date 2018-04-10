package com.tingfeng.service.impl;

import com.tingfeng.dao.PersonRepository;
import com.tingfeng.model.Person;
import com.tingfeng.service.PersonService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PersonServiceImpl implements PersonService {

    @Autowired
    private PersonRepository personRepository;

    public Person save(Person person) {
        // If this username is not used then return null, if is used then return this Person
        return personRepository.save(person.getId(), person);
    }

    public Person findPersonByUsername(String name){
        return personRepository.findByUsername(name);
    }

}
