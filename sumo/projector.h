#ifndef PROJECTOR_H_HM85FIRS
#define PROJECTOR_H_HM85FIRS

struct Point {
    double x;
    double y;
};

struct Wgs84Point;

class Projector
{
public:
    typedef void* proj_t;
    Projector(const char* projStr);
    ~Projector();
    Projector(const Projector&) = delete;
    Projector& operator=(const Projector&) = delete;
    Wgs84Point project(const Point&);
    void offset(double x, double y);

private:
    proj_t mProjection;
    double mOffsetX;
    double mOffsetY;
};

#endif /* PROJECTOR_H_HM85FIRS */

