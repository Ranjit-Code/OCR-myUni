package org.myuniv.system.course.services;

import org.myuniv.system.course.beans.dto.CourseDto;
import org.springframework.stereotype.Service;

import java.util.List;

@Service public interface CoursesService {
    CourseDto createCourse(CourseDto courseDto);

    CourseDto updateCourse(CourseDto courseDto);

    CourseDto retrieveCourse(Long courseId);

    List<CourseDto> retrieveCourses();

    void deleteCourse(Long courseId);
}
