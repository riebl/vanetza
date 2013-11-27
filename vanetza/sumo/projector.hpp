#ifndef PROJECTOR_HPP_HM85FIRS
#define PROJECTOR_HPP_HM85FIRS

namespace vanetza
{

struct Wgs84Point;

class Projector
{
public:
    typedef void* proj_t;
    Projector(const char* projStr);
    ~Projector();
    Projector(const Projector&) = delete;
    Projector& operator=(const Projector&) = delete;
    Wgs84Point project(double x, double y);
    void offset(double x, double y);

private:
    proj_t mProjection;
    double mOffsetX;
    double mOffsetY;
};

} // namespace vanetza

#endif /* PROJECTOR_HPP_HM85FIRS */

