#ifndef STORED_POSITION_PROVIDER_HPP_12MUJV0K
#define STORED_POSITION_PROVIDER_HPP_12MUJV0K

#include <vanetza/common/position_provider.hpp>

namespace vanetza
{

/**
 * StoredPositionProvider is a very simple PositionProvider:
 * it always returns the previously stored position fix
 */
class StoredPositionProvider : public PositionProvider
{
public:
    const PositionFix& position_fix() override
    {
        return m_position;
    }

    void position_fix(const PositionFix& pos)
    {
        m_position = pos;
    }

private:
    PositionFix m_position;
};

} // namespace vanetza

#endif /* STORED_POSITION_PROVIDER_HPP_12MUJV0K */

