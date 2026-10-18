#ifndef OBJECT_CONTAINER_HPP_25SOHVUH
#define OBJECT_CONTAINER_HPP_25SOHVUH

#include <cassert>
#include <functional>
#include <map>
#include <memory>
#include <typeindex>
#include <type_traits>
#include <utility>

namespace vanetza
{

class ObjectContainer
{
private:
    using object_handle = std::unique_ptr<void, std::function<void(void*)>>;
    using container_type = std::map<std::type_index, object_handle>;

public:
    ObjectContainer() = default;

    // no copy
    ObjectContainer(const ObjectContainer&) = delete;
    ObjectContainer& operator=(const ObjectContainer&) = delete;

    // allow move
    ObjectContainer(ObjectContainer&&) = default;
    ObjectContainer& operator=(ObjectContainer&&) = default;

    bool empty() const { return m_container.empty(); }

    std::size_t size() const { return m_container.size(); }

    void clear() { m_container.clear(); }

    template<typename T>
    void erase()
    {
        m_container.erase(std::type_index(typeid(T)));
    }

    template<typename T>
    T* find()
    {
        T* result = nullptr;
        auto found = m_container.find(std::type_index(typeid(T)));
        if (found != m_container.end()) {
            result = static_cast<T*>(found->second.get());
        }
        return result;
    }

    template<typename T>
    const T* find() const
    {
        const T* result = nullptr;
        auto found = m_container.find(std::type_index(typeid(T)));
        if (found != m_container.end()) {
            result = static_cast<const T*>(found->second.get());
        }
        return result;
    }

    /**
     * Insert an object into container
     * \param obj object owned by a unique pointer, possibly with a custom deleter
     * \return true if inserted, false if an object of this type is already present
     */
    template<typename T, typename D>
    bool insert(std::unique_ptr<T, D> obj)
    {
        static_assert(std::is_object<T>() && !std::is_const<T>(),
                "Only non-const objects are supported by ObjectContainer");
        static_assert(!std::is_reference<D>(),
                "Deleter references are not supported by ObjectContainer");
        object_handle handle {
            obj.release(),
            [d = std::move(obj.get_deleter())](void* ptr) mutable { d(static_cast<T*>(ptr)); }
        };
        return m_container.emplace(std::type_index(typeid(T)), std::move(handle)).second;
    }

    template<typename T>
    T& get()
    {
        static_assert(std::is_default_constructible<T>(),
                "Only default constructible types are accessible through ObjectContainer::get");
        T* result = find<T>();
        if (!result) {
            std::unique_ptr<T> obj { new T() };
            result = obj.get();
            if (!insert(std::move(obj)))
                result = nullptr;
        }
        assert(result);
        return *result;
    }

private:
    container_type m_container;
};

} // namespace vanetza

#endif /* OBJECT_CONTAINER_HPP_25SOHVUH */

