#include "projector.h"
#include "vanetza/gnss/wgs84point.h"
#include "vanetza/units/angle.h"
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

Wgs84Point Projector::project(double x, double y)
{
    projUV p;
    p.u = x - mOffsetX;
    p.v = y - mOffsetY;
    p = pj_inv(p, mProjection);
    return Wgs84Point { p.v % units::rad, p.u % units::rad };
}
