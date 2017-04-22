#ifndef OBJECT_CONTAINER_HPP_25SOHVUH
#define OBJECT_CONTAINER_HPP_25SOHVUH

#include <functional>
#include <map>
#include <memory>
#include <typeindex>
#include <type_traits>

namespace vanetza
{

class ObjectContainer
{
private:
    struct object_handle
    {
        template<typename T>
        object_handle(std::unique_ptr<T> obj) :
            object(obj.release()),
            deleter([](void* ptr) { std::default_delete<T>()(static_cast<T*>(ptr)); })
        {
        }

        ~object_handle() {
            deleter(object);
            object = nullptr;
        }

        void* object;
        std::function<void(void*)> deleter;
    };
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
            result = static_cast<T*>(found->second.object);
        }
        return result;
    }

    template<typename T>
    const T* find() const
    {
        const T* result = nullptr;
        auto found = m_container.find(std::type_index(typeid(T)));
        if (found != m_container.end()) {
            result = static_cast<const T*>(found->second.object);
        }
        return result;
    }

    template<typename T>
    bool insert(std::unique_ptr<T> obj)
    {
        static_assert(std::is_object<T>() && !std::is_const<T>(),
                "Only non-const objects are supported by ObjectContainer");
        return m_container.emplace(std::type_index(typeid(T)), std::move(obj)).second;
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

