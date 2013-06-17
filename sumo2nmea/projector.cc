#include "angle.h"
#include "projector.h"
#include "wgs84point.h"
#include <proj_api.h>

Projector::Projector(const char* projStr) :
    mProjection(pj_init_plus(projStr)),
    mOffsetX(0.0), mOffsetY(0.0)
{
}

Projector::~Projector()
{
    pj_free(mProjection);
}

void Projector::offset(double x, double y)
{
    mOffsetX = x;
    mOffsetY = y;
}

Wgs84Point Projector::project(const Point& point)
{
    projUV p;
    p.u = point.x - mOffsetX;
    p.v = point.y - mOffsetY;
    p = pj_inv(p, mProjection);
    return Wgs84Point { p.u % units::rad, p.v % units::rad };
}
